#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#define ONETIME_PREKEYS_NUMBER 100
#define OMEMO_INFO "OMEMO X3DH"
#define SECRET_LEN 64
#define SECRET_RTX_LEN 32
#define AES_KEY_LEN	crypto_aead_aes256gcm_KEYBYTES
#define NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define AES_MESSAGE_LEN (NONCE_LEN + crypto_aead_aes256gcm_ABYTES)
#define MESSAGE_KEY_LEN 32
#define MESSAGE_LEN (AES_MESSAGE_LEN + MESSAGE_KEY_LEN + AES_MESSAGE_LEN)

#define DIR_NAME ".cmemo"
#define MAX_PATH_LEN 100
#define UNITS_DIR "units"
#define UNIT_DIR_LEN 32 
#define PRIVATE_BUNDLE_FILE "private.bl"
#define PUBLIC_BUNDLE_FILE "public.bl"
#define SECRET_RX_FILE "secret_rx.sk"
#define SECRET_TX_FILE "secret_tx.sk"

#define MAX_BUNDLE_LEN 4000
#define MAX_STDIN_LEN 8000
#define F_INIT_S "-i"
#define F_INIT_L "--init"
#define F_ADD_S "-a"
#define F_ADD_L "--add"
#define F_LIST_S "-l"
#define F_LIST_L "--list"
#define F_FINGER_S "-f"
#define F_FINGER_L "--finger-print"
#define F_EXPORT_S "-x"
#define F_EXPORT_L "--export"
#define F_ENCODE_S "-e"
#define F_ENCODE_L "--encoding"

#define F_UNIT_S "-u"
#define F_UNIT_L "--unit"

#define F_REQUEST_S "-q"
#define F_REQUEST_L "--request"
#define F_RESPONSE_S "-p"
#define F_RESPONSE_L "--response"

#define F_RECV_S "-r"
#define F_RECV_L "--recv"
#define F_SEND_S "-s"
#define F_SEND_L "--send"

extern int errno;

typedef struct {
	char exists;
	char arg_req;
	char *arg;
} farg_t;

typedef struct {
	farg_t init;
	farg_t add;
	farg_t list;
	farg_t finger;
	farg_t export;
	farg_t encode;
	farg_t unit;
	farg_t request;
	farg_t response;
	farg_t send;
	farg_t recv;
} fargs_t;

typedef struct {
	unsigned char *public;
	unsigned char *private;
} keypair_t;

typedef struct {
	unsigned char indentity[crypto_sign_PUBLICKEYBYTES];
	unsigned char signed_prekey[crypto_box_PUBLICKEYBYTES];
	unsigned char **onetime_prekeys;
	int opks_number;
	int *opks_ids;
} bundle_public_t;

typedef struct {
	unsigned char indentity[crypto_sign_SECRETKEYBYTES];
	unsigned char signed_prekey[crypto_box_SECRETKEYBYTES];
	unsigned char **onetime_prekeys;
	int opks_number;
	int *opks_ids;
} bundle_private_t;

typedef struct {
	int len_i;
	int len_s;
	unsigned char *indentity;
	unsigned char *signed_prekey;
	unsigned char ***onetime_prekeys;
	int *opks_number;
	int **opks_ids;
	char has_sig;
	unsigned char *spk_sig;
} bundle_pointer_t;

typedef struct {
	bundle_public_t public;
	bundle_private_t private;
} bundle_t;

typedef struct {
	unsigned char message[MESSAGE_KEY_LEN];
	unsigned char wrap[MESSAGE_KEY_LEN];
	unsigned char next_sk[SECRET_RTX_LEN];
} message_keys_t;

typedef struct {
	unsigned char key[SECRET_RTX_LEN];
	unsigned char nonce[NONCE_LEN];
} secret_t;

typedef struct {
	unsigned char *data;
	unsigned long long len;
} message_t;

void print_bin_hex(unsigned char *bin, int len) {
	const size_t hex_maxlen = (len * 2) + 1;
	char *hex = malloc(hex_maxlen);
	sodium_bin2hex(hex, hex_maxlen, bin, len);

	printf("%s\n", hex);
	free(hex);
}

void bin_to_hex(unsigned char **bin, int *len) {
	const size_t hex_maxlen = (*len * 2) + 1;
	unsigned char *hex = malloc(sizeof(unsigned char) 
							    * hex_maxlen);
	sodium_bin2hex((char *)hex, hex_maxlen, 
				   *bin, *len);
	free(*bin);
	*bin = hex;
	*len = strlen((const char *)(hex));
}

int hex_to_bin(unsigned char **hex, int *len) {
	int status = 0;
	const size_t bin_maxlen = (*len / 2) + 1;
	unsigned char *bin = malloc(sizeof(unsigned char) 
							    * bin_maxlen);
	size_t bin_len;
	status = sodium_hex2bin(bin, bin_maxlen, 
						    (char *)(*hex), *len,
				   			NULL, &bin_len, 
						 	NULL );
	free(*hex);
	*hex = bin;
	*len = (int)bin_len;

	return status;
}

void bin_to_base64(unsigned char **bin, int *len) {
	const int variat = sodium_base64_VARIANT_URLSAFE;
	const size_t b64_maxlen = sodium_base64_encoded_len(*len, 
														 variat);
	unsigned char *b64 = malloc(sizeof(unsigned char) 
							    * b64_maxlen);
	
	sodium_bin2base64((char *)b64, b64_maxlen,
                      *bin, *len,
                      variat);
	free(*bin);
	*bin = b64;
	*len = strlen((const char *)(b64));
}

int base64_to_bin(unsigned char **b64, int *len) {
	int status = 0;
	const int variat = sodium_base64_VARIANT_URLSAFE;
	const size_t bin_maxlen = (*len / 4 * 3) + 1;

	unsigned char *bin = malloc(sizeof(unsigned char) 
							    * bin_maxlen);
	size_t bin_len;
	status = sodium_base642bin(bin, bin_maxlen, 
							   (char *)(*b64), *len,
								NULL, &bin_len, 
								NULL, variat );
	free(*b64);
	*b64 = bin;
	*len = (int)bin_len;

	return status;
}

int bin_fingerprint(char **hex,
					 unsigned char *bin, int blen) {
	int hashlen = crypto_generichash_BYTES;

	unsigned char fp[hashlen];
	if (crypto_generichash(fp, hashlen, 
					   	   bin, blen, 
						   NULL, 0) != 0) {
		return 1;
	}
	const size_t hex_maxlen = (hashlen * 2) + 1;
	*hex = malloc(hex_maxlen);
	sodium_bin2hex(*hex, hex_maxlen, fp, hashlen);

	return 0;
}
void bundle_to_bin(unsigned char **binp, int *len,
				   bundle_pointer_t *bp) {
	int len_i = bp->len_i;
	int len_s = bp->len_s;
	int len_o = bp->len_s;
	int len_int = sizeof(int);
	int opks_n = *bp->opks_number;

	*len = len_i + len_s 
		   + (len_s * opks_n)
		   + (len_int * opks_n)
		   + len_int;

	if (bp->has_sig == 1) {
		*len += crypto_sign_BYTES;
	}

	*binp = malloc(sizeof(unsigned char *) * *len);
	unsigned char *bin = *binp;

	memcpy(bin, bp->indentity, len_i);
	bin += len_i;
	memcpy(bin, bp->signed_prekey, len_s);
	bin += len_s;

	if (bp->has_sig == 1) {
		if (bp->spk_sig != NULL) {
			memcpy(bin, bp->spk_sig, 
		           crypto_sign_BYTES);
		}
		bin += crypto_sign_BYTES;
	}

	memcpy(bin, bp->opks_number, len_int);
	bin += len_int;

	int *opks_ids = *bp->opks_ids;
	unsigned char **opks = *bp->onetime_prekeys;

	for (int i = 0; i < opks_n; i++) {
		memcpy(bin, &opks_ids[i], len_int);
		bin += len_int;
		memcpy(bin, opks[i], len_o);
		bin += len_o;
	}
}


void bin_to_bundle(bundle_pointer_t *bp, unsigned char *bin) {
	int len_i = bp->len_i;
	int len_s = bp->len_s;
	int len_o = bp->len_s;
	int len_int = sizeof(int);

	memcpy(bp->indentity, bin, len_i);
	bin += len_i;
	memcpy(bp->signed_prekey, bin, len_s);
	bin += len_s;

	if (bp->has_sig == 1) {
		if (bp->spk_sig != NULL) {
			memcpy(bp->spk_sig, bin, 
		           crypto_sign_BYTES);
		}
		bin += crypto_sign_BYTES;
	}

	memcpy(bp->opks_number, bin, len_int);
	bin += len_int;

	int opks_n = *bp->opks_number;
	int *opks_ids = malloc(len_int * opks_n);
	unsigned char **opks = malloc(sizeof(unsigned char *) * opks_n);

	*bp->opks_ids = opks_ids;
	*bp->onetime_prekeys = opks;

	for (int i = 0; i < opks_n; i++) {
		opks[i] = malloc(sizeof(unsigned char *) * len_o);

		memcpy(&opks_ids[i], bin, len_int);
		bin += len_int;
		memcpy(opks[i], bin, len_o);
		bin += len_o;
	}
}

void secret_to_bin(unsigned char *bin, secret_t *sc) {
	memcpy(bin, sc->nonce, sizeof(sc->nonce));
	memcpy(bin + sizeof(sc->nonce), sc->key, sizeof(sc->key));
}

void bin_to_secret(secret_t *sc, unsigned char *bin) {
	memcpy(sc->nonce, bin, sizeof(sc->nonce));
	memcpy(sc->key, bin + sizeof(sc->nonce), sizeof(sc->key));
}

int generate_sign_keypair(keypair_t *keypair) {
	return crypto_sign_keypair(keypair->public, keypair->private);
}

int generate_exchange_keypair(keypair_t *keypair) {
	randombytes_buf(keypair->private, crypto_box_SECRETKEYBYTES);
	return crypto_scalarmult_base(keypair->public, keypair->private);
}

int get_index_from_ids(int id, int *ids, int ids_number) {
	int index = -1;
	for (int i = 0; i < ids_number; i++) {
		if (ids[i] == id) {
			index = i;
			break;
		}
	}
	return index;
}

int scalarmult_keypairs(keypair_t *pairs, int len, unsigned char **scs) {
	for (int i = 0; i < len; i++) {
		keypair_t p = pairs[i];
		scs[i] = malloc(crypto_scalarmult_BYTES);
		if (crypto_scalarmult(scs[i], p.private, p.public) != 0) {
			return 1;
		}
	}
	return 0;
}

void concat_array(unsigned char **array, int alen, 
				  unsigned char *concat, int clen) {
	for (int i = 0; i < alen; i++) {
		memcpy(concat + clen * i, array[i], clen);
	}   
}

unsigned char *get_opk_by_id(unsigned char **opks, int len, int *ids, int id) {
	int opk_index = get_index_from_ids(id, ids, len);
	if (opk_index == -1) {
		return NULL;
	}
	return opks[opk_index];
}

void aes_encrypt(message_t *enmsg, message_t *msg,
				 unsigned char *key) {
	unsigned char nonce[NONCE_LEN];
	randombytes_buf(nonce, sizeof(nonce));

	crypto_aead_aes256gcm_encrypt(enmsg->data + NONCE_LEN, 
							      &enmsg->len,
                            	  msg->data, 
							      msg->len,
                              	  NULL, 0,
                              	  NULL, nonce, key);

	memcpy(enmsg->data, nonce, NONCE_LEN);
	enmsg->len += NONCE_LEN;
}

int aes_decrypt(message_t *demsg, message_t *msg,
				unsigned char *key) {
	unsigned char nonce[NONCE_LEN];
	memcpy(nonce, msg->data, NONCE_LEN);

	return crypto_aead_aes256gcm_decrypt(demsg->data, 
									     &demsg->len,
									  	 NULL,
									  	 msg->data + NONCE_LEN, 
									     msg->len - NONCE_LEN,
									  	 NULL, 0,
									  	 nonce, key);
}

void derive_message_keys(message_keys_t *keys, secret_t *secret) {
	crypto_kdf_derive_from_key(keys->message, MESSAGE_KEY_LEN, 0, 
							   (const char *)secret->nonce, secret->key);
	crypto_kdf_derive_from_key(keys->wrap, MESSAGE_KEY_LEN, 1, 
							   OMEMO_INFO, secret->key);
	crypto_kdf_derive_from_key(keys->next_sk, SECRET_RTX_LEN, 2, 
							   OMEMO_INFO, secret->key);
}

void encrypt_message(message_t *enmsg, unsigned char *next_sk,
					 message_t *msg, secret_t *secret) {
	message_keys_t keys;
	derive_message_keys(&keys, secret);
	memcpy(next_sk, keys.next_sk, SECRET_RTX_LEN);

	message_t wrapped;
	wrapped.len = AES_MESSAGE_LEN + MESSAGE_KEY_LEN;
	wrapped.data = malloc(sizeof(unsigned char *) * wrapped.len);
	message_t msg_key = {keys.message, MESSAGE_KEY_LEN};
	aes_encrypt(&wrapped, &msg_key, keys.wrap);

	message_t cmsg = {
		enmsg->data + wrapped.len,
		enmsg->len - wrapped.len
	};
	aes_encrypt(&cmsg, msg, keys.message);

	memcpy(enmsg->data, wrapped.data, wrapped.len);

	free(wrapped.data);
}

int decrypt_message(message_t *demsg, unsigned char *next_sk, 
					message_t *msg, secret_t *secret) {
	message_keys_t keys;
	derive_message_keys(&keys, secret);
	memcpy(next_sk, keys.next_sk, SECRET_RTX_LEN);

	message_t wrapped;
	wrapped.len = AES_MESSAGE_LEN + MESSAGE_KEY_LEN;
	wrapped.data = malloc(sizeof(unsigned char *) * wrapped.len);
	memcpy(wrapped.data, msg->data, wrapped.len);

	message_t msg_key;
	msg_key.len = MESSAGE_KEY_LEN;
	msg_key.data = malloc(sizeof(unsigned char *) * msg_key.len);
	if (aes_decrypt(&msg_key, &wrapped, keys.wrap) != 0) {
		free(wrapped.data);
		free(msg_key.data);
		return 1;
	}

	message_t cmsg = {
		msg->data + wrapped.len,
		msg->len - wrapped.len
	};
	if (aes_decrypt(demsg, &cmsg, msg_key.data) != 0) {
		free(wrapped.data);
		free(msg_key.data);
		return 2;
	}

	free(wrapped.data);
	free(msg_key.data);

	return 0;
}

void nonce_message(message_t *nmsg, unsigned char *next_n, 
				   message_t *msg) {
	randombytes_buf(next_n, NONCE_LEN);
	
	nmsg->len = msg->len + NONCE_LEN;
	nmsg->data = malloc(sizeof(unsigned char *) * nmsg->len);

	memcpy(nmsg->data + NONCE_LEN, msg->data, msg->len);
	memcpy(nmsg->data, next_n, NONCE_LEN);
}

void unnonce_message(message_t *msg, unsigned char *next_n, 
				   message_t *nmsg) {
	msg->len = nmsg->len - NONCE_LEN;
	msg->data = malloc(sizeof(unsigned char *) * msg->len);

	memcpy(next_n, nmsg->data, NONCE_LEN);
	memcpy(msg->data, nmsg->data + NONCE_LEN, msg->len);
}

int create_bundle(bundle_t *bundle) {
	keypair_t indentity = {
		.public = bundle->public.indentity, 
		.private = bundle->private.indentity, 
	};
	if (generate_sign_keypair(&indentity) != 0) {
		fprintf(stderr, "Failed to generate indentity bundle.\n");
		return 1;
	}

	keypair_t signed_prekey = {
		.public = bundle->public.signed_prekey, 
		.private = bundle->private.signed_prekey, 
	};
	if (generate_exchange_keypair(&signed_prekey) != 0) {
		fprintf(stderr, "Failed to generate signed prekey bundle.\n");
		return 2; 
	}

	bundle->public.opks_number = ONETIME_PREKEYS_NUMBER;
	bundle->private.opks_number = ONETIME_PREKEYS_NUMBER;
	int opk_pub_len = sizeof(unsigned char *) 
					* bundle->public.opks_number;
	int opk_priv_len = sizeof(unsigned char *) 
					 * bundle->private.opks_number;

	bundle->public.onetime_prekeys = malloc(opk_pub_len);
	bundle->private.onetime_prekeys = malloc(opk_priv_len);
	bundle->public.opks_ids = malloc(sizeof(int) * ONETIME_PREKEYS_NUMBER);
	bundle->private.opks_ids = malloc(sizeof(int) * ONETIME_PREKEYS_NUMBER);

	for (int i = 0; i < ONETIME_PREKEYS_NUMBER; i++) {
		bundle->public.onetime_prekeys[i] = malloc(crypto_box_PUBLICKEYBYTES);
		bundle->private.onetime_prekeys[i] = malloc(crypto_box_SECRETKEYBYTES);

		keypair_t onetime_prekey = {
			.public = bundle->public.onetime_prekeys[i], 
			.private = bundle->private.onetime_prekeys[i], 
		};
		if (generate_exchange_keypair(&onetime_prekey) != 0) {
			fprintf(stderr, "Failed to generate one-time prekey bundle.\n");
			return 3;
		}
		bundle->public.opks_ids[i] = i;
		bundle->private.opks_ids[i] = i;
	}

	return 0;
}

int request_secret_key(unsigned char *indentity_sk, 
					   bundle_public_t *bundle,
					   unsigned char *prekey_sig,
					   int opk_id,
					   unsigned char *ephemeral_pk,
					   unsigned char *secret_key) {

	if (crypto_sign_verify_detached(prekey_sig,
								 	bundle->signed_prekey,
								 	sizeof(bundle->signed_prekey),
								 	bundle->indentity) != 0) {
		fprintf(stderr, "Incorrect signed prekey signature.\n");
		return 1;
	}

	unsigned char indentity_x_sk[crypto_scalarmult_curve25519_BYTES];
	if (crypto_sign_ed25519_sk_to_curve25519(indentity_x_sk, 
										     indentity_sk) != 0) {
		return 2;
	}

	unsigned char ephemeral_sk[crypto_box_SECRETKEYBYTES];
	keypair_t ephemeral_pair = {
		.public = ephemeral_pk,
		.private = ephemeral_sk
	};
	if (generate_exchange_keypair(&ephemeral_pair) != 0) {
		fprintf(stderr, "Failed to generate ephemeral keypair.\n");
		return 3;
	}

	unsigned char *onetime_prekey = get_opk_by_id(bundle->onetime_prekeys,
											      bundle->opks_number,
												  bundle->opks_ids,
											   	  opk_id);
	if (onetime_prekey == NULL) {
		fprintf(stderr, "Not valid onetime prekey id.\n");
		return 4;
	}

	int sc_pairs_len = 4;
	keypair_t sc_pairs[] = {
		{
			.public = bundle->signed_prekey,
			.private = indentity_x_sk
		},
		{
			.public = bundle->indentity,
			.private = ephemeral_sk
		},
		{
			.public = bundle->signed_prekey,
			.private = ephemeral_sk
		},
		{
			.public = onetime_prekey,
			.private = ephemeral_sk
		}
	};

	unsigned char *dhs[sc_pairs_len];
	scalarmult_keypairs(sc_pairs, sc_pairs_len, dhs);

	unsigned char dh_concat[crypto_scalarmult_BYTES * sc_pairs_len];
	concat_array(dhs, sc_pairs_len, dh_concat, crypto_scalarmult_BYTES);
	for (int i = 0; i < sc_pairs_len; i++) {
		free(dhs[i]);
	}

	crypto_kdf_derive_from_key(secret_key, SECRET_LEN, 0, 
							   OMEMO_INFO, dh_concat);

	return 0;
}

int response_secret_key(bundle_private_t *bundle,
					   	 int opk_id,
						 unsigned char *indentity_pk,
					   	 unsigned char *ephemeral_pk,
					   	 unsigned char *secret_key) {

	unsigned char indentity_x_pk[crypto_scalarmult_curve25519_BYTES];
	if (crypto_sign_ed25519_pk_to_curve25519(indentity_x_pk,
										     indentity_pk) !=0) {
		return 1;
	}

	unsigned char *onetime_prekey = get_opk_by_id(bundle->onetime_prekeys,
											      bundle->opks_number,
												  bundle->opks_ids,
											   	  opk_id);
	if (onetime_prekey == NULL) {
		fprintf(stderr, "Not valid onetime prekey id.\n");
		return 2;
	}

	int sc_pairs_len = 4;
	keypair_t sc_pairs[] = {
		{
			.public = indentity_x_pk,
			.private = bundle->signed_prekey
		},
		{
			.public = ephemeral_pk,
			.private = bundle->indentity
		},
		{
			.public = ephemeral_pk,
			.private = bundle->signed_prekey
		},
		{
			.public = ephemeral_pk,
			.private = onetime_prekey
		}
	};

	unsigned char *dhs[sc_pairs_len];
	scalarmult_keypairs(sc_pairs, sc_pairs_len, dhs);

	unsigned char dh_concat[crypto_scalarmult_BYTES * 4];
	concat_array(dhs, 4, dh_concat, crypto_scalarmult_BYTES);
	for (int i = 0; i < sc_pairs_len; i++) {
		free(dhs[i]);
	}


	crypto_kdf_derive_from_key(secret_key, SECRET_LEN, 0, 
							   OMEMO_INFO, dh_concat);

	return 0;
}

void split_secret_key(unsigned char *secret_rx, 
					  unsigned char *secret_tx,
					  unsigned char *secret) {
	memcpy(secret_rx, secret, SECRET_RTX_LEN);
	memcpy(secret_tx, secret + SECRET_RTX_LEN, SECRET_RTX_LEN);
}

void send_message(message_t *enmsg, secret_t *next_secret,
				  message_t *msg, secret_t *secret) {
	message_t msgn;
	nonce_message(&msgn, next_secret->nonce, msg);

	enmsg->len = MESSAGE_LEN + msgn.len;
	enmsg->data = malloc(sizeof(unsigned char *) * enmsg->len);

	encrypt_message(enmsg, next_secret->key, &msgn, secret);

	free(msgn.data);
}

int receive_message(message_t *msg, secret_t *next_secret,
				  	message_t *enmsg, secret_t *secret) {
	message_t msgn;
	msgn.len = enmsg->len - MESSAGE_LEN;
	msgn.data = malloc(sizeof(unsigned char *) * msgn.len);

	if (decrypt_message(&msgn, next_secret->key, enmsg, secret) != 0) {
		free(msgn.data);
		return 1;
	}

	unnonce_message(msg, next_secret->nonce, &msgn);

	free(msgn.data);
	return 0;
}

void make_bundle_pub_pointer(bundle_pointer_t *bp,
							 bundle_public_t *b,
							 char has_sig,
							 unsigned char *spk_sig) {
	bp->len_i = sizeof(b->indentity);
	bp->len_s = sizeof(b->signed_prekey);
	bp->indentity = b->indentity;
	bp->signed_prekey = b->signed_prekey;
	bp->onetime_prekeys = &b->onetime_prekeys;
	bp->opks_number = &b->opks_number;
	bp->opks_ids = &b->opks_ids;
	bp->has_sig = has_sig;
	bp->spk_sig = spk_sig;
}

void make_bundle_priv_pointer(bundle_pointer_t *bp,
							  bundle_private_t *b) {
	bp->len_i = sizeof(b->indentity);
	bp->len_s = sizeof(b->signed_prekey);
	bp->indentity = b->indentity;
	bp->signed_prekey = b->signed_prekey;
	bp->onetime_prekeys = &b->onetime_prekeys;
	bp->opks_number = &b->opks_number;
	bp->opks_ids = &b->opks_ids;
	bp->has_sig = 0;
	bp->spk_sig = NULL;
}

void free_bundle_pub(bundle_public_t *bundle) {
	for (int i = 0; i < bundle->opks_number; i++ ) {
		free(bundle->onetime_prekeys[i]);
	}
	free(bundle->onetime_prekeys);
	free(bundle->opks_ids);
}

void free_bundle_priv(bundle_private_t *bundle) {
	for (int i = 0; i < bundle->opks_number; i++ ) {
		free(bundle->onetime_prekeys[i]);
	}
	free(bundle->onetime_prekeys);
	free(bundle->opks_ids);
}

void free_bundle(bundle_t *bundle) {
 	free_bundle_pub(&bundle->public);
 	free_bundle_priv(&bundle->private);
}

void pathcat(char *base, char *add) {
	strcat(base, "/");
	strcat(base, add);
}

void make_path(char *path, char *base, 
			   char *add) {
	memcpy(path, base, strlen(base) + 1);
	pathcat(path, add);
}

void get_work_dir(char *dir) {
	char *home = getenv("HOME");
	make_path(dir, home, DIR_NAME);
}


int get_full_dir_name(char *name, int len, 
					  char *dir, char *prefix) {
	DIR *dirp = opendir(dir);

	if (dirp == NULL) {
		fprintf(stderr, "Can not open directory.\n");
        return 1;
    }

	char found = 0;	
	struct dirent *dp;
	while ((dp = readdir(dirp)) != NULL) {
        if (dp->d_type != 4 
            || strcmp(dp->d_name, ".") == 0 
            || strcmp(dp->d_name, "..") == 0) {
           	continue; 
        }

		if (strncmp(prefix, dp->d_name, 
			  		strlen(prefix)) == 0) {
			memcpy(name, dp->d_name, len - 1);
			name[len] = '\0';
			found = 1; 
			break;
		}
    }
	closedir(dirp);

	if (found == 0) {
		fprintf(stderr, "Directory not found.\n");
		return 1;
	}

	return 0;
}

int read_bin(unsigned char *bin, int *len,
			 FILE *f) {
	if (errno == ENOENT) {
		return 1;
	}

	*len = 0;
	int byte;
	while ((byte = fgetc(f)) != EOF) {
		unsigned char c = (unsigned char)byte;
		bin[*len] = c;
		(*len)++;
	}
	return 0;
}

int write_bin(unsigned char *bin, int len,
			  FILE *f) {
	int wlen = fwrite(bin, sizeof(unsigned char), 
					  len, f);

	if (wlen != len) {
		return 1;
	}
	return 0;
}


int read_secret(secret_t *s, FILE *f) {
	int len = 0;	
	unsigned char bin[NONCE_LEN + SECRET_RTX_LEN];	

	if (read_bin(bin, &len, f) != 0) {
		return 1;
	}
	bin_to_secret(s, bin);

	return 0;
}

int write_secret(secret_t *s, FILE *f) {
	int len = NONCE_LEN + SECRET_RTX_LEN;	
	unsigned char bin[len];	
	secret_to_bin(bin, s);

	return write_bin(bin, len, f);
}

int load_secret(secret_t *s,
				char *dir, char *name) {
	int status;
	char path[MAX_PATH_LEN];	
	make_path(path, dir, name);

	FILE *f = fopen(path, "r");
	status = read_secret(s, f);

	fclose(f);
	return status;
}


int store_secret(secret_t *s,
				 char *dir, char *name) {
	int status;
	char path[MAX_PATH_LEN];	
	make_path(path, dir, name);

	FILE *f = fopen(path, "w");
	status = write_secret(s, f);

	fclose(f);
	return status;
}

int read_bundle_pointer(bundle_pointer_t *bp,
						FILE *f) {
	int len;
	unsigned char *bin = malloc(sizeof(unsigned char *)
							    * MAX_BUNDLE_LEN);
	if (read_bin(bin, &len, f) != 0) {
		free(bin);
		return 1;
	}
	bin_to_bundle(bp, bin);

	free(bin);
	return 0;
}

int write_bundle_pointer(bundle_pointer_t *bp,
						 FILE *f) {
	int len;	
	unsigned char *bin;	
	bundle_to_bin(&bin, &len, bp);

	if (write_bin(bin, len, f) != 0) {
		free(bin);
		return 1;
	}

	free(bin);
	return 0;
}

int load_bundle_pointer(bundle_pointer_t *bp, 
						char *dir, char *name) {
	int status;
	char path[MAX_PATH_LEN];	
	make_path(path, dir, name);

	FILE *f = fopen(path, "r");
	status = read_bundle_pointer(bp, f);

	fclose(f);
	return status;
}

int store_bundle_pointer(bundle_pointer_t *bp, 
						 char *dir, char *name) {
	int status;
	char path[MAX_PATH_LEN];	
	make_path(path, dir, name);

	FILE *f = fopen(path, "w");
	status = write_bundle_pointer(bp, f);

	chmod(path, S_IRUSR | S_IWUSR);

	fclose(f);
	return status;
}

int get_unit_dir(char *udir, char *dir, char *unit){
	char name[UNIT_DIR_LEN];
	if (get_full_dir_name(name, UNIT_DIR_LEN, 
					   	  dir, unit) != 0) {
		fprintf(stderr, "Unit not found.\n");
		return 1;
	}
	make_path(udir, dir, name);

	return 0;
}

int store_unit_bundle(bundle_pointer_t *bp,
					  char *dir) {
	int status;

	status = mkdir(dir, S_IRWXU);

	if (status != 0 && errno != EEXIST) {
		fprintf(stderr, "Unable to store unit bundle.\n");
		return 1;
	}

	char *fp;
	if (bin_fingerprint(&fp, bp->indentity, 
					 	bp->len_i) != 0) {
		free(fp);
		return 2;
	}

	char name[UNIT_DIR_LEN];
	memcpy(name, fp, UNIT_DIR_LEN - 1);
	free(fp);
	name[UNIT_DIR_LEN] = '\0';

	char path[MAX_PATH_LEN];
	make_path(path, dir, name);
	status = mkdir(path, S_IRWXU);

	if (store_bundle_pointer(bp, path, 
						     PUBLIC_BUNDLE_FILE) != 0) {
		return 3;
	}

	return 0;
}

int load_unit_bundle(bundle_pointer_t *bp, char *dir) {
	if (load_bundle_pointer(bp, dir, 
						    PUBLIC_BUNDLE_FILE) != 0) {
		return 1;
	}

	return 0;
}

int store_bundle(bundle_t *bundle, char *dir) {
	int status;

	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, 
					     bundle->public.signed_prekey, 
					     sizeof(bundle->public.signed_prekey), 
					  	 bundle->private.indentity);

	bundle_pointer_t pub_bl_p;
	make_bundle_pub_pointer(&pub_bl_p, 
						    &bundle->public,
						 	1, sig);
	bundle_pointer_t priv_bl_p;
	make_bundle_priv_pointer(&priv_bl_p, 
						     &bundle->private);

	status = store_bundle_pointer(&pub_bl_p, dir, 
					     		  PUBLIC_BUNDLE_FILE);
	status = store_bundle_pointer(&priv_bl_p, dir, 
							      PRIVATE_BUNDLE_FILE);
	return status;
}

int load_bundle(bundle_t *bundle, char *dir) {
	int status;

	bundle_pointer_t pub_bl_p;
	make_bundle_pub_pointer(&pub_bl_p, 
	 					    &bundle->public,
	 					 	1, NULL);
	bundle_pointer_t priv_bl_p;
	make_bundle_priv_pointer(&priv_bl_p, 
	 					     &bundle->private);

	status = load_bundle_pointer(&pub_bl_p, dir, 
	 				     		 PUBLIC_BUNDLE_FILE);
	status = load_bundle_pointer(&priv_bl_p, dir, 
							     PRIVATE_BUNDLE_FILE);

	return status;
}


int init(char *work_dir) {
	int status;
	status = mkdir(work_dir, S_IRWXU);

	if (status != 0 && errno != EEXIST) {
		fprintf(stderr, "Unable to init.\n");
		return 1;
	}
	
	bundle_t bundle;
	create_bundle(&bundle);

	status = store_bundle(&bundle, work_dir);

	free_bundle(&bundle);	
	return 0;
}

void request(char *unit,unsigned char *ephemeral_pk, 
			 char *nonce, int opk_id, 
			 char *work_dir) {
	bundle_t bl;
	load_bundle(&bl, work_dir);

	unsigned char *sig = malloc(sizeof(unsigned char *) 
							    * crypto_sign_BYTES);
	bundle_public_t unit_bl;
	bundle_pointer_t unit_bl_p;
	make_bundle_pub_pointer(&unit_bl_p, 
						    &unit_bl,
						    1, sig);
	char udir[MAX_PATH_LEN];		
	make_path(udir, work_dir, UNITS_DIR);
	get_unit_dir(udir, udir, unit);
	load_unit_bundle(&unit_bl_p, udir);

	unsigned char secret[SECRET_LEN];
	request_secret_key(bl.private.indentity,
					   &unit_bl,
					   sig,
					   opk_id,
					   ephemeral_pk,
					   secret);

	secret_t srx;
	secret_t stx;
	split_secret_key(srx.key, stx.key,
				  	 secret);

	memcpy(srx.nonce, nonce, NONCE_LEN);
	memcpy(stx.nonce, nonce, NONCE_LEN);

	store_secret(&srx, udir, SECRET_RX_FILE);
	store_secret(&stx, udir, SECRET_TX_FILE);

	free(sig);
	free_bundle_pub(&unit_bl);
	free_bundle(&bl);
}

void response(char *unit, unsigned char *ephemeral_pk, 
			  char *nonce, int opk_id,
			  char *work_dir) {
	bundle_t bl;
	load_bundle(&bl, work_dir);

	bundle_public_t unit_bl;
	bundle_pointer_t unit_bl_p;
	make_bundle_pub_pointer(&unit_bl_p, 
						    &unit_bl,
						    1, NULL);

	char udir[MAX_PATH_LEN];		
	make_path(udir, work_dir, UNITS_DIR);
	get_unit_dir(udir, udir, unit);
	load_unit_bundle(&unit_bl_p, udir);

	unsigned char secret[SECRET_LEN];
	response_secret_key(&bl.private,
					    opk_id,
					    unit_bl.indentity,
					    ephemeral_pk,
					    secret);

	secret_t srx;
	secret_t stx;
	split_secret_key(stx.key, srx.key,
				  	 secret);

	memcpy(srx.nonce, nonce, NONCE_LEN);
	memcpy(stx.nonce, nonce, NONCE_LEN);

	store_secret(&srx, udir, SECRET_RX_FILE);
	store_secret(&stx, udir, SECRET_TX_FILE);

	free_bundle_pub(&unit_bl);
	free_bundle(&bl);
}

void send(message_t *enmsg, message_t *msg,
		  char *unit, char *work_dir) {
	char udir[MAX_PATH_LEN];		
	make_path(udir, work_dir, UNITS_DIR);
	get_unit_dir(udir, udir, unit);

	secret_t s;	
	load_secret(&s, udir, SECRET_TX_FILE);

	send_message(enmsg, &s, msg, &s);

	store_secret(&s, udir, SECRET_TX_FILE);
}

int receive(message_t *msg, message_t *enmsg,
		  char *unit, char *work_dir) {
	int status = 0;
	char udir[MAX_PATH_LEN];		
	make_path(udir, work_dir, UNITS_DIR);
	get_unit_dir(udir, udir, unit);

	secret_t s;	
	load_secret(&s, udir, SECRET_RX_FILE);

	status = receive_message(msg, &s, enmsg, &s);

	store_secret(&s, udir, SECRET_RX_FILE);

	return status;
}

int arg_is(char *arg, char **funcs) {
	int i = 0;
	char *func;
	while ((func = funcs[i]) != NULL) {
		if (strcmp(arg, func) == 0) {
			return 1;
		}
		i++;
	}
	return 0;
}

void load_args(fargs_t *fargs, char *argv[], int c) {
	fargs->init.exists = 0;
	fargs->init.arg_req = 0;
	fargs->add.exists = 0;
	fargs->add.arg_req = 0;
	fargs->list.exists = 0;
	fargs->list.arg_req = 0;
	fargs->finger.exists = 0;
	fargs->finger.arg_req = 0;
	fargs->export.exists = 0;
	fargs->export.arg_req = 0;
	fargs->encode.exists = 0;
	fargs->encode.arg_req = 0;

	fargs->unit.exists = 0;
	fargs->unit.arg_req = 1;

	fargs->request.exists = 0;
	fargs->request.arg_req = 1;
	fargs->response.exists = 0;
	fargs->response.arg_req = 1;

	fargs->recv.exists = 0;
	fargs->recv.arg_req = 0;
	fargs->send.exists = 0;
	fargs->send.arg_req = 0;

	int f_i = 0;
	int arg_i = 0;
	char **args[5];
	for (int i = 1; i < c; i++) {
		char *arg = argv[i];

		char *init[] = {
			F_INIT_S, 	F_INIT_L,
			NULL
		};
		char *add[]	 = {
			F_ADD_S, 	F_ADD_L,
			NULL
		};
		char *list[]	 = {
			F_LIST_S, 	F_LIST_L,
			NULL
		};
		char *finger[]	 = {
			F_FINGER_S, F_FINGER_L,
			NULL
		};
		char *export[] 	= {
			F_EXPORT_S,	F_EXPORT_L,
			NULL
		};
		char *encode[] 	= {
			F_ENCODE_S, F_ENCODE_L,
			NULL
		};
		char *unit[] 	= {
			F_UNIT_S,	F_UNIT_L, 
			NULL
		};
		char *request[]	= {
			F_REQUEST_S,F_REQUEST_L,
			NULL
		};
		char *response[]= {
			F_RESPONSE_S,F_RESPONSE_L,
			NULL
		};
		char *receive[] = {
			F_RECV_S,	F_RECV_L,
			NULL
		};
		char *send[]	= {
			F_SEND_S, 	F_SEND_S,
			NULL
		};

		if (arg_is(arg, init)) {
			fargs->init.exists = 1;
		} else if (arg_is(arg, add)) {
			fargs->add.exists = 1;
		} else if (arg_is(arg, list)) {
			fargs->list.exists = 1;
		} else if (arg_is(arg, finger)) {
			fargs->finger.exists = 1;
		} else if (arg_is(arg, export)) {
			fargs->export.exists = 1;
		} else if (arg_is(arg, encode)) {
			fargs->encode.exists = 1;
		} else if (arg_is(arg, unit)) {
			fargs->unit.exists = 1;
			args[f_i] = &fargs->unit.arg;
			f_i++;
		} else if (arg_is(arg, request)) {
			fargs->request.exists = 1;
			args[f_i] = &fargs->request.arg;
			f_i++;
		} else if (arg_is(arg, response)) {
			fargs->response.exists = 1;
			args[f_i] = &fargs->response.arg;
			f_i++;
		} else if (arg_is(arg, receive)) {
			fargs->recv.exists = 1;
		} else if (arg_is(arg, send)) {
			fargs->send.exists = 1;
		} else {
			*args[arg_i] = arg;
			arg_i++;
		}
	}
}

int main(int argc, char *argv[]) {
    if (sodium_init() == -1) {
        fprintf(stderr, "Libsodium initialization failed\n");
        return 1;
    }
	if (crypto_aead_aes256gcm_is_available() == 0) {
		abort();
	}

	fargs_t fargs;
	load_args(&fargs, argv, argc);

	char work_dir[MAX_PATH_LEN];
	get_work_dir(work_dir);

	if (fargs.init.exists == 1) {
		init(work_dir);
	} else if (fargs.export.exists == 1) {
		char path[MAX_PATH_LEN];	
		make_path(path, work_dir, PUBLIC_BUNDLE_FILE);
		FILE *f = fopen(path, "r");

		int len = 0;
		unsigned char *bin = malloc(sizeof(unsigned char)
			   	  					* MAX_BUNDLE_LEN);
		read_bin(bin, &len, f);

		if (fargs.encode.exists == 1) {
			bin_to_base64(&bin, &len);
		}
		fprintf(stdout, "%s", bin);
	} else if (fargs.add.exists == 1) {
		unsigned char *sig = malloc(sizeof(unsigned char *)
									* crypto_sign_BYTES);
		bundle_public_t bl;
		bundle_pointer_t bl_p;
		make_bundle_pub_pointer(&bl_p,
								&bl,
								1, sig);
		int len = 0;
		int mlen = MAX_BUNDLE_LEN;
		if (fargs.encode.exists == 1) {
			mlen *= 2;
		}
		unsigned char *bin = malloc(sizeof(unsigned char)
			   	  					* mlen);
		read_bin(bin, &len, stdin);
		if (fargs.encode.exists == 1) {
			base64_to_bin(&bin, &len);
		}

		bin_to_bundle(&bl_p, bin);

		char dir[MAX_PATH_LEN];	
		make_path(dir, work_dir, UNITS_DIR);
		store_unit_bundle(&bl_p, dir);

		free(sig);
		free_bundle_pub(&bl);
		free(bin);
	} else if (fargs.request.exists == 1
			   && fargs.unit.exists == 1) {
		int opk_id = 0;
       	char nonce[NONCE_LEN + 1];

		char *arg = fargs.request.arg;
		opk_id = (int)strtol(arg + NONCE_LEN + 1, NULL, 10);
		memcpy(nonce, arg, NONCE_LEN);
		nonce[NONCE_LEN] = '\0';

		int len = (int)crypto_box_PUBLICKEYBYTES;
		unsigned char *ephemeral_pk;
		ephemeral_pk = malloc(sizeof(unsigned char) 
							  * len);
    	request(fargs.unit.arg, ephemeral_pk, nonce, opk_id, work_dir);

		if (fargs.encode.exists == 1) {
			bin_to_base64(&ephemeral_pk, &len);
		}
		fprintf(stdout, "%s", ephemeral_pk);

		free(ephemeral_pk);
	} else if (fargs.response.exists == 1
			   && fargs.unit.exists == 1) {
		int opk_id = 0;
       	char nonce[NONCE_LEN + 1];

		char *arg = fargs.response.arg;
		opk_id = (int)strtol(arg + NONCE_LEN + 1, NULL, 10);
		memcpy(nonce, arg, NONCE_LEN);
		nonce[NONCE_LEN] = '\0';

		int len = (int)crypto_box_PUBLICKEYBYTES;
		unsigned char *ephemeral_pk = malloc(sizeof(unsigned char) 
							          * len);
		read_bin(ephemeral_pk, &len, stdin);
		ephemeral_pk[len - 1] = '\0';

		if (fargs.encode.exists == 1) {
			base64_to_bin(&ephemeral_pk, &len);
		}

        response(fargs.unit.arg, ephemeral_pk, nonce, opk_id, work_dir);
	} else if (fargs.recv.exists == 1
			   && fargs.unit.exists == 1) {
		int len = 0;
		unsigned char *msgb = malloc(sizeof(unsigned char)
			   	  					* MAX_STDIN_LEN);
		read_bin(msgb, &len, stdin);

		if (len == 1) {
			free(msgb);
			return 0;
		}

		if (fargs.encode.exists == 1) {
			base64_to_bin(&msgb, &len);
		}

		message_t enmsg = {
			.data = msgb,
			.len = len, 
		};
		message_t msg;
		if (receive(&msg, &enmsg, 
			        fargs.unit.arg, work_dir) != 0) {
			fprintf(stderr, "Can not decrypt message.\n");
		} else {
			msg.data[msg.len] = '\0';
			fprintf(stdout, "%s", msg.data);
		}

		free(msgb);
		free(msg.data);
	} else if (fargs.send.exists == 1
			   && fargs.unit.exists == 1) {
		int len = 0;
		unsigned char *msgb = malloc(sizeof(unsigned char)
			   	  					* MAX_STDIN_LEN);
		read_bin(msgb, &len, stdin);

		message_t msg = {
			.data = msgb,
			.len = len, 
		};
		message_t enmsg;
		send(&enmsg, &msg, fargs.unit.arg, work_dir);

		if (fargs.encode.exists == 1) {
			int hl = enmsg.len;
			bin_to_base64(&enmsg.data, &hl);
		}
		fprintf(stdout, "%s", enmsg.data);

		free(msgb);
		free(enmsg.data);
	} else if (fargs.list.exists == 1) {
		char dir[MAX_PATH_LEN];	
		make_path(dir, work_dir, UNITS_DIR);

		DIR *dirp = opendir(dir);

		if (dirp == NULL) {
			fprintf(stderr, "Can not open directory.\n");
			return 1;
		}

		struct dirent *dp;
		while ((dp = readdir(dirp)) != NULL) {
			if (dp->d_type != 4 
				|| strcmp(dp->d_name, ".") == 0 
				|| strcmp(dp->d_name, "..") == 0) {
				continue; 
			}

			fprintf(stdout, "%s\n", dp->d_name);
		}
		closedir(dirp);
	} else if (fargs.finger.exists == 1) {
		bundle_t bl;
		load_bundle(&bl, work_dir);

		char *fp;
		if (bin_fingerprint(&fp, bl.public.indentity, 
							sizeof(bl.public.indentity)) != 0) {
			fprintf(stderr, "Error to make indentity fingerprint.\n");
		} else {
			fprintf(stdout, "%s\n", fp);
		}

		free_bundle(&bl);
		free(fp);
	}

    return 0;
}
