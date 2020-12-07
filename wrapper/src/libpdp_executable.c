#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <openssl/bn.h>
#include <pdp.h>
#include <pdp/cpor.h>
#include <pdp/cpor_types.h>
#include "time_it.h"

#define DELIMITER ";"
#define ARRAY_DELIMITER ","

#define ERROR(...) \
    do { \
        fprintf(stderr, "\n[ERROR] %s: ", __FUNCTION__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        fflush(stderr); \
    } while(0)

typedef struct {
    int index;
    const char *name;
} opts_desc_t;

const opts_desc_t opts_desc[] = {
    {-1, "Required arguments"},
    {0, " [filename], the name of file to process"},
    {-1, "Operation arguments"},
    {16, ", split file"},
    {2, ", generate keys"},
    {3, ", tag the file"},
    {4, ", challenge the file"},
    {5, ", generate a proof in response to a challenge"},
    {6, ", verify the file"},
    {7, ", display this usage message"},
    {23, ", verify using file proof"},
    {-1, "Operation parameters"},
    {18, " [string] base64 encoded key string"},
    {19, " [string] base64 encoded pk string"},
    {20, " [string] base64 encoded challenge string"},
    {21, " [string] base64 encoded proof string"},
    {-1, "CPOR algorithm OPTIONS"},
    {17, " [num], block index"},
    {22, " [num], number of blocks"},
    {8, " [num], select non-default challenge param"},
    {9, " [num], select non-default block size"},
    {10, " [num], select non-default sector size"},
    {11, " [bits], bit-length of prime over which Z_p is generated"},
    {12, " [bytes], PRF key length"},
    {13, " [bytes], encryption key length"},
    {14, " [bytes], MAC key length"}
#ifdef _THREAD_SUPPORT
    ,{15, " [num], number of threads"}
#endif //_THREAD_SUPPORT
};

const struct option long_opts[] = {
    {"filename", required_argument, NULL, 'f'},
    {"ofilename", required_argument, NULL, 'o'},
    {"keys", no_argument, NULL, 'K'},
    {"tag", no_argument, NULL, 'T'},
    {"challenge", no_argument, NULL, 'C'},
    {"prove", no_argument, NULL, 'P'},
    {"verify", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {"cparam", required_argument, NULL, 'l'},
    {"blocksize", required_argument, NULL, 's'},
    {"sectorsize", required_argument, NULL, 'm'},
    {"lambda", required_argument, NULL, '~'},
    {"prf_key_size", required_argument, NULL, '1'},
    {"enc_key_size", required_argument, NULL, '2'},
    {"mac_key_size", required_argument, NULL, '3'},
    {"numthreads", required_argument, NULL, 'r'},
    {"split", no_argument, NULL, 'S'},
    {"block", required_argument, NULL, 'b'},
    {"keystring", required_argument, NULL, 'k'},
    {"pkstring", required_argument, NULL, 'j'},
    {"challengestring", required_argument, NULL, 'c'},
    {"proofstring", required_argument, NULL, 'p'},
    {"numchunks", required_argument, NULL, 'n'},
    {"verifyfile", no_argument, NULL, 'W'},
    {0, 0, 0, 0}
};

void usage(const char *arg) {
    printf("Usage:\n\t%s -f [file] [operations] [OPTIONS]\n", arg);
    for (int i = 0; i < sizeof(opts_desc) / sizeof(opts_desc_t); i++) {
        if (opts_desc[i].index < 0) {
            printf("\n%s:\n", opts_desc[i].name);
        } else {
            printf("\t--%s%s\n", long_opts[opts_desc[i].index].name, opts_desc[i].name);
        }
    }
}

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64invs[80];

void b64_generate_decode_table() {
    size_t i;

    memset(b64invs, -1, sizeof(b64invs));
    for (i=0; i<sizeof(b64chars)-1; i++) {
        b64invs[b64chars[i]-43] = i;
    }
}

size_t b64_encoded_size(size_t inlen) {
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

int b64_isvalidchar(char c) {
    if (c >= '0' && c <= '9')
        return 1;
    if (c >= 'A' && c <= 'Z')
        return 1;
    if (c >= 'a' && c <= 'z')
        return 1;
    if (c == '+' || c == '/' || c == '=')
        return 1;
    return 0;
}

size_t b64_decoded_size(const char *in) {
    size_t len;
    size_t ret;
    size_t i;

    if (in == NULL)
        return 0;

    len = strlen(in);
    ret = len / 4 * 3;

    for (i=len; i-->0; ) {
        if (in[i] == '=') {
            ret--;
        } else {
            break;
        }
    }

    return ret;
}

char *b64_encode(const char *in) {
    size_t len = strlen(in);

    char   *out;
    size_t  elen;
    size_t  i;
    size_t  j;
    size_t  v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out  = malloc(elen+1);
    out[elen] = '\0';

    for (i=0, j=0; i<len; i+=3, j+=4) {
        v = in[i];
        v = i+1 < len ? v << 8 | in[i+1] : v << 8;
        v = i+2 < len ? v << 8 | in[i+2] : v << 8;

        out[j]   = b64chars[(v >> 18) & 0x3F];
        out[j+1] = b64chars[(v >> 12) & 0x3F];
        if (i+1 < len) {
            out[j+2] = b64chars[(v >> 6) & 0x3F];
        } else {
            out[j+2] = '=';
        }
        if (i+2 < len) {
            out[j+3] = b64chars[v & 0x3F];
        } else {
            out[j+3] = '=';
        }
    }

    return out;
}

char *b64_decode(const char *in) {
    b64_generate_decode_table();
    size_t outlen = 1000000;
    char *out = malloc(outlen * sizeof(char));
    memset(out, '\0', outlen);

    size_t len;
    size_t i;
    size_t j;
    int    v;

    if (in == NULL)
        return NULL;

    len = strlen(in);
    if (outlen < b64_decoded_size(in) || len % 4 != 0)
        return NULL;

    for (i=0; i<len; i++) {
        if (!b64_isvalidchar(in[i])) {
            return NULL;
        }
    }

    for (i=0, j=0; i<len; i+=4, j+=3) {
        v = b64invs[in[i]-43];
        v = (v << 6) | b64invs[in[i+1]-43];
        v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
        v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

        out[j] = (v >> 16) & 0xFF;
        if (in[i+2] != '=')
            out[j+1] = (v >> 8) & 0xFF;
        if (in[i+3] != '=')
            out[j+2] = v & 0xFF;
    }

    return out;
}

char *uint_to_str(unsigned int num) {
    char *output = malloc(0);
    sprintf(output, "%u", num);
    return output;
}

char *serialize_key(pdp_key_t key) {
    char *output = malloc(1000000 * sizeof(char));
    pdp_cpor_key_t *cpor_key = key.cpor;

    char *k_enc_str = malloc(cpor_key->k_enc_size * 4 * sizeof(unsigned char) + 1);
    k_enc_str[0] = '\0';
    for (int i = 0; i < cpor_key->k_enc_size; i++) {
        if (i > 0) {
            strcat(k_enc_str, ",");
        }
        strcat(k_enc_str, uint_to_str((unsigned int) cpor_key->k_enc[i]));
    }

    char *k_mac_str = malloc(cpor_key->k_mac_size * 4 * sizeof(unsigned char) + 1);
    k_mac_str[0] = '\0';
    for (int i = 0; i < cpor_key->k_mac_size; i++) {
        if (i > 0) {
            strcat(k_mac_str, ",");
        }
        strcat(k_mac_str, uint_to_str((unsigned int) cpor_key->k_mac[i]));
    }

    sprintf(output,
        "%u;%u;%s;%s;%s",
        (unsigned int) cpor_key->k_enc_size, (unsigned int) cpor_key->k_mac_size,
        k_enc_str, k_mac_str, BN_bn2hex(cpor_key->Zp));

    free(k_enc_str);
    free(k_mac_str);
    return b64_encode(output);
}

void deserialize_key(pdp_key_t *key, const char *str) {
    char *decoded = b64_decode(str);

    pdp_cpor_key_t *cpor_key = malloc(sizeof(pdp_cpor_key_t));
    key->cpor = cpor_key;

    char *k_enc_str = NULL;
    char *k_mac_str = NULL;

    char *part;
    part = strtok(decoded, DELIMITER);
    cpor_key->k_enc_size = atoi(part);

    part = strtok(NULL, DELIMITER);
    cpor_key->k_mac_size = atoi(part);
    part = strtok(NULL, DELIMITER);

    if (cpor_key->k_enc_size > 0) {
        k_enc_str = malloc(strlen(part) * sizeof(char) + 1);
        strcpy(k_enc_str, part);
        part = strtok(NULL, DELIMITER);
    }

    if (cpor_key->k_mac_size > 0) {
        k_mac_str = malloc(strlen(part) * sizeof(char) + 1);
        strcpy(k_mac_str, part);
        part = strtok(NULL, DELIMITER);
    }

    cpor_key->Zp = BN_new();
    BN_hex2bn(&cpor_key->Zp, part);

    cpor_key->k_enc = malloc(cpor_key->k_enc_size * sizeof(unsigned char));
    char *k_enc_str_part = strtok(k_enc_str, ARRAY_DELIMITER);
    for (int i = 0; i < cpor_key->k_enc_size; i++) {
        cpor_key->k_enc[i] = atoi(k_enc_str_part);
        k_enc_str_part = strtok(NULL, ARRAY_DELIMITER);
    }
    free(k_enc_str);

    cpor_key->k_mac = malloc(cpor_key->k_mac_size * sizeof(unsigned char));
    char *k_mac_str_part = strtok(k_mac_str, ARRAY_DELIMITER);
    for (int i = 0; i < cpor_key->k_mac_size; i++) {
        cpor_key->k_mac[i] = atoi(k_mac_str_part);
        k_mac_str_part = strtok(NULL, ARRAY_DELIMITER);
    }
    free(k_mac_str);
}

char *serialize_challenge(pdp_challenge_t challenge) {
    char *output = malloc(1000000 * sizeof(char));
    pdp_cpor_challenge_t *cpor_chal = challenge.cpor;

    char I[1000000];
    memset(I, '\0', sizeof(I));
    for (int i = 0; i < cpor_chal->ell; i++) {
        if (i > 0) {
            strcat(I, ",");
        }
        strcat(I, uint_to_str(cpor_chal->I[i]));
    }

    char nu[1000000];
    memset(nu, '\0', sizeof(nu));
    for (int i = 0; i < cpor_chal->ell; i++) {
        if (i > 0) {
            strcat(nu, ",");
        }
        strcat(nu, BN_bn2hex(cpor_chal->nu[i]));
    }

    sprintf(output,
        "%u;%s;%u;%u;%s;",
        cpor_chal->ell, I, cpor_chal->I_size, cpor_chal->nu_size, nu);
    return b64_encode(output);
}

void deserialize_challenge(pdp_challenge_t *challenge, const char *str) {
    char *decoded = b64_decode(str);

    pdp_cpor_challenge_t *cpor_chal = malloc(sizeof(pdp_cpor_challenge_t));
    challenge->cpor = cpor_chal;

    char *part;
    part = strtok(decoded, DELIMITER);
    cpor_chal->ell = atoi(part);

    part = strtok(NULL, DELIMITER);
    char *I_str = malloc(strlen(part) * sizeof(char) + 1);
    strcpy(I_str, part);

    part = strtok(NULL, DELIMITER);
    cpor_chal->I_size = atoi(part);

    part = strtok(NULL, DELIMITER);
    cpor_chal->nu_size = atoi(part);

    part = strtok(NULL, DELIMITER);
    char *nu_str = malloc(strlen(part) * sizeof(char) + 1);
    strcpy(nu_str, part);

    cpor_chal->I = malloc(cpor_chal->ell * sizeof(unsigned int));
    char *I_str_part = strtok(I_str, ARRAY_DELIMITER);
    for (int i = 0; i < cpor_chal->ell; i++) {
        cpor_chal->I[i] = atoi(I_str_part);
        I_str_part = strtok(NULL, ARRAY_DELIMITER);
    }
    free(I_str);

    cpor_chal->nu = malloc(cpor_chal->ell * sizeof(BIGNUM *));
    char *nu_str_part = strtok(nu_str, ARRAY_DELIMITER);
    for (int i = 0; i < cpor_chal->ell; i++) {
        cpor_chal->nu[i] = BN_new();
        BN_hex2bn(&cpor_chal->nu[i], nu_str_part);
        nu_str_part = strtok(NULL, ARRAY_DELIMITER);
    }
    free(nu_str);
}

char *serialize_proof(pdp_proof_t proof) {
    char *output = malloc(1000000 * sizeof(char));
    pdp_cpor_proof_t *cpor_proof = proof.cpor;

    char mu[1000000];
    memset(mu, '\0', sizeof(mu));
    for (int i = 0; i < cpor_proof->mu_size / 8; i++) {
        if (i > 0) {
            strcat(mu, ",");
        }
        strcat(mu, BN_bn2hex(cpor_proof->mu[i]));
    }

    sprintf(output,
        "%s;%s;%u;",
        BN_bn2hex(cpor_proof->sigma), mu, cpor_proof->mu_size);
    return b64_encode(output);
}

void deserialize_proof(pdp_proof_t *proof, const char *str) {
    char *decoded = b64_decode(str);

    pdp_cpor_proof_t *cpor_proof = malloc(sizeof(pdp_cpor_proof_t));
    proof->cpor = cpor_proof;

    char *part;
    part = strtok(decoded, DELIMITER);
    cpor_proof->sigma = BN_new();
    BN_hex2bn(&cpor_proof->sigma, part);

    part = strtok(NULL, DELIMITER);
    char *mu_str = malloc(strlen(part) * sizeof(char) + 1);
    strcpy(mu_str, part);

    part = strtok(NULL, DELIMITER);
    cpor_proof->mu_size = atoi(part);

    cpor_proof->mu = malloc(cpor_proof->mu_size / 8 * sizeof(BIGNUM *));
    char *mu_str_part = strtok(mu_str, ARRAY_DELIMITER);
    for (int i = 0; i < cpor_proof->mu_size / 8; i++) {
        cpor_proof->mu[i] = BN_new();
        BN_hex2bn(&cpor_proof->mu[i], mu_str_part);
        mu_str_part = strtok(NULL, ARRAY_DELIMITER);
    }
    free(mu_str);
}

int initialize(pdp_ctx_t *ctx, char *filename, int argc, char **argv) {
    time_it_init();

    PDP_SELECT(ctx, PDP_CPOR);
    int error = 0;
    if ((error = pdp_ctx_init(ctx))) {
        ERROR("Could not initialize context (%d).", error);
        return error;
    }

#ifdef _THREAD_SUPPORT
	ctx->opts |= PDP_OPT_THREADED;
#endif //_THREAD_SUPPORT

    int opt = -1;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "b:l:s:m:~:1:2:3:r:", long_opts, NULL)) != -1) {
        switch(opt) {
            case 'b': {
                unsigned int block = atoi(optarg);
                char new_filename[500];
                sprintf(new_filename, "%s.c_%u", filename, block);
                strcpy(filename, new_filename);
                break;
            }
            case 'l':
                ctx->cpor_param->num_challenge_blocks = atoi(optarg);
                break;
            case 's':
                ctx->cpor_param->block_size = atoi(optarg);
                break;
            case 'm':
                ctx->cpor_param->sector_size = atoi(optarg);
                break;
            case '~':
                ctx->cpor_param->lambda = atoi(optarg);
                break;
            case '1':
                ctx->cpor_param->prf_key_size = atoi(optarg);
                break;
            case '2':
                ctx->cpor_param->enc_key_size = atoi(optarg);
                break;
            case '3':
                ctx->cpor_param->mac_key_size = atoi(optarg);
                break;
            case 'r': {
                unsigned int num_threads = atoi(optarg);
                if (ctx->opts & PDP_OPT_THREADED) {
                    ctx->num_threads = num_threads;
                }
                break;
            }
        }
    }

    if ((error = pdp_ctx_create(ctx, filename, NULL))) {
        ERROR("Could not create context (%d).", error);
        return error;
    }

    return 0;
}

int load_key(pdp_ctx_t *ctx, pdp_key_t *key, pdp_key_t *pk, const char *keypath) {
    int error = 0;
    if ((error = pdp_key_open(ctx, key, pk, keypath)) != 0) {
        ERROR("Keys not found (%d).", error);
        return error;
    }

    return 0;
}

int generate_key(pdp_ctx_t *ctx, pdp_key_t *key, pdp_key_t *pk) {
    int error = 0;
    if ((error = pdp_key_gen(ctx, key, pk)) != 0) {
        ERROR("Could not generate keys (%d).", error);
        return error;
    }

    return 0;
}

int store_key(pdp_ctx_t *ctx, pdp_key_t *key, const char *keypath) {
    int error = 0;
    if ((error = pdp_key_store(ctx, key, keypath)) != 0) {
        ERROR("Could not store keys at [%s]", keypath);
        return error;
    }

    return 0;
}

int tag_file(pdp_ctx_t *ctx, pdp_key_t *key, pdp_tag_t *tag) {
    int error = 0;
    if ((error = pdp_file_preprocess(ctx))) {
        ERROR("Could not pre-process file (%d).", error);
        return error;
    }

    if ((error = pdp_tags_gen(ctx, key, tag))) {
        ERROR("Could not generate tags (%d).", error);
        return error;
    }

    if ((error = pdp_store(ctx, key, tag))) {
        ERROR("Could not store tags (%d).", error);
        return error;
    }

    return 0;
}

int generate_challenge(pdp_ctx_t *ctx, pdp_key_t *key, pdp_challenge_t *ver_chal) {
    int error = 0;
    if ((error = pdp_challenge_gen(ctx, key, ver_chal))) {
        ERROR("Could not generate challenge (%d).", error);
        return error;
    }

    return 0;
}

int generate_proof(pdp_ctx_t *ctx, pdp_key_t *pk, pdp_challenge_t *prv_chal, pdp_proof_t *proof) {
    int error = 0;
    if ((error = pdp_proof_gen(ctx, pk, prv_chal, proof))) {
        ERROR("Could not generate proof (%d).", error);
        return error;
    }

    return 0;
}

int verify_proof(pdp_ctx_t *ctx, pdp_key_t *key, pdp_challenge_t *ver_chal, pdp_proof_t *proof) {
    int proof_stat = 0;
    proof_stat = pdp_proof_verify(ctx, key, ver_chal, proof);
    if (proof_stat == -1) {
        ERROR("Could not verify proof (%d).", proof_stat);
        return proof_stat;
    }

    return proof_stat;
}

int verify_file_proof(pdp_ctx_t *ctx, pdp_key_t *key, pdp_challenge_t *ver_chal) {
    FILE *file = NULL;
    char filepath[500];
    char *proofstring = NULL;
    pdp_proof_t proof;

    memset(filepath, 0, sizeof(filepath));
    snprintf(filepath, sizeof(filepath), "%s.proof", ctx->ofilepath);
    file = fopen(filepath, "rb");
    if(file == NULL){
      return -1;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    proofstring = (char*) malloc(sizeof(char) * size);
    fread(proofstring, 1, size, file);
    fclose(file);

    proofstring[size - 1] = '\0';

    memset(&proof, 0, sizeof(pdp_proof_t));
    deserialize_proof(&proof, proofstring);

    return verify_proof(ctx, key, ver_chal, &proof);
}

int split_file(const char *filename, unsigned int num_parts) {
    FILE *file = fopen(filename, "rb");

    long file_size = 0;
    if (file) {
        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
    }

    unsigned int chunk_size = file_size / num_parts;
    if (file_size % num_parts) {
        chunk_size++;
    }

    unsigned char *buf = NULL;
    size_t buf_len = chunk_size * sizeof(unsigned char);
    if ((buf = malloc(buf_len)) == NULL) {
        return -1;
    }

    for (int i = 0; i < num_parts; i++) {
        if (i == num_parts - 1) { // calculate size of last part
            buf_len = file_size - (chunk_size * (num_parts - 1));
        }
        memset(buf, 0, buf_len);

        fseek(file, i * chunk_size, SEEK_SET);
        fread(buf, 1, buf_len, file);

        char chunk_name[100];
        memset(chunk_name, '\0', sizeof(chunk_name));
        sprintf(chunk_name, "%s.c_%d", filename, i);

        FILE *new_file = fopen(chunk_name, "wb");
        if (new_file) {
            fwrite(buf, buf_len, 1, new_file);
        } else {
            ERROR("Could not write to file: %s", chunk_name);
        }
        fclose(new_file);
    }

    free(buf);
    fclose(file);

    return 0;
}

int main(int argc, char **argv) {
    char *filename = NULL;

    char OPT_SPLIT_FILE = 0;
    char OPT_GENERATE_KEY = 0;
    char OPT_TAG_FILE = 0;
    char OPT_GENERATE_CHALLENGE = 0;
    char OPT_GENERATE_PROOF = 0;
    char OPT_VERIFY_PROOF = 0;
    char OPT_VERIFY_FILE_PROOF = 0;

    char *key_string = NULL;
    char *pk_string = NULL;
    char *challenge_string = NULL;
    char *proof_string = NULL;

    unsigned int num_parts = 1;

    int opt = -1;
    while ((opt = getopt_long(argc, argv, "f:k:j:c:p:n:SKTVPCWh", long_opts, NULL)) != -1) {
        switch(opt) {
            case 'f':
                filename = optarg;
                break;
            case 'k':
                key_string = optarg;
                break;
            case 'j':
                pk_string = optarg;
                break;
            case 'c':
                challenge_string = optarg;
                break;
            case 'p':
                proof_string = optarg;
                break;
            case 'n':
                num_parts = atoi(optarg);
                break;
            case 'S':
                OPT_SPLIT_FILE = 1;
                break;
            case 'K':
                OPT_GENERATE_KEY = 1;
                break;
            case 'T':
                OPT_TAG_FILE = 1;
                break;
            case 'V':
                OPT_VERIFY_PROOF = 1;
                break;
            case 'P':
                OPT_GENERATE_PROOF = 1;
                break;
            case 'C':
                OPT_GENERATE_CHALLENGE = 1;
                break;
            case 'W':
                OPT_VERIFY_FILE_PROOF = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
        }
    }

    if (filename == NULL) {
        usage(argv[0]);
        return -1;
    }

    // INIT
    pdp_ctx_t context, *ctx = &context;
    memset(&context, 0, sizeof(pdp_ctx_t));
    if (initialize(ctx, filename, argc, argv) != 0) {
        ERROR("Failed to initialize library.");
        return 1;
    }

    // SPLIT_FILE
    if (OPT_SPLIT_FILE) {
        split_file(filename, num_parts);
        return 0;
    }

    // GEN_KEY
    pdp_key_t key, pk;
    if (OPT_GENERATE_KEY) {
        memset(&key, 0, sizeof(pdp_key_t));
        memset(&pk, 0, sizeof(pdp_key_t));

        if (generate_key(ctx, &key, &pk) != 0) {
            ERROR("Failed to generate key.");
            return 1;
        }

        printf("{\"keystring\":\"%s\",", serialize_key(key));
        printf("\"pkstring\":\"%s\"}\n", serialize_key(pk));
    }

    if (key_string != NULL) {
        memset(&key, 0, sizeof(pdp_key_t));
        deserialize_key(&key, key_string);
    }

    if (pk_string != NULL) {
        memset(&pk, 0, sizeof(pdp_key_t));
        deserialize_key(&pk, pk_string);
    }

    // TAG_FILE
    pdp_tag_t tag;
    memset(&tag, 0, sizeof(pdp_tag_t));
    if (OPT_TAG_FILE) {
        if (tag_file(ctx, &key, &tag) != 0) {
            ERROR("Failed to tag file.");
            return 1;
        }
    }

    // GEN_CHALLENGE
    pdp_challenge_t ver_chal;
    pdp_challenge_t prv_chal;
    if (OPT_GENERATE_CHALLENGE) {
        memset(&ver_chal, 0, sizeof(pdp_challenge_t));
        memset(&prv_chal, 0, sizeof(pdp_challenge_t));

        if (generate_challenge(ctx, &key, &ver_chal) != 0) {
            ERROR("Failed to generate challenge.");
            return 1;
        }

        pdp_challenge_for_prover(ctx, &ver_chal, &prv_chal);

        printf("{\"challengestring\":\"%s\"}\n", serialize_challenge(ver_chal));
    }

    if (challenge_string != NULL) {
        memset(&ver_chal, 0, sizeof(pdp_challenge_t));
        memset(&prv_chal, 0, sizeof(pdp_challenge_t));

        deserialize_challenge(&ver_chal, challenge_string);
        pdp_challenge_for_prover(ctx, &ver_chal, &prv_chal);
    }

    // GEN_PROOF
    pdp_proof_t proof;
    if (OPT_GENERATE_PROOF) {
        memset(&proof, 0, sizeof(pdp_proof_t));

        if (generate_proof(ctx, &pk, &prv_chal, &proof) != 0) {
            ERROR("Failed to generate proof.");
            return 1;
        }

        printf("{\"proofstring\":\"%s\"}\n", serialize_proof(proof));
    }

    if (proof_string != NULL) {
        memset(&proof, 0, sizeof(pdp_proof_t));
        deserialize_proof(&proof, proof_string);
    }

    // VERIFY_PROOF
    if (OPT_VERIFY_PROOF) {
        int proof_stat = verify_proof(ctx, &key, &ver_chal, &proof);
        printf("{\"verify\":\"%s\"}\n", proof_stat ? "false" : "true");
    }
    else if (OPT_VERIFY_FILE_PROOF) {
        int proof_stat = verify_file_proof(ctx, &key, &ver_chal);
        printf("{\"verify\":\"%s\"}\n", proof_stat ? "false" : "true");
    }

    return 0;
}
