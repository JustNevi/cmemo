#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>

#define ONETIME_PREKEYS_NUMBER 100
#define OMEMO_INFO "OMEMO X3DH"
#define SECRET_LEN 64
#define SECRET_RTX_LEN 32
#define AES_KEY_LEN	crypto_aead_aes256gcm_KEYBYTES
#define NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define AES_MESSAGE_LEN (NONCE_LEN + crypto_aead_aes256gcm_ABYTES)
#define MESSAGE_KEY_LEN 32
#define MESSAGE_LEN (AES_MESSAGE_LEN + MESSAGE_KEY_LEN + AES_MESSAGE_LEN)

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

void encrypt_message(message_t *enmsg, message_t *msg,
					 secret_t *secret, unsigned char *next_sk) {
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

int decrypt_message(message_t *demsg, message_t *msg,
					 secret_t *secret, unsigned char *next_sk) {
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

void split_secret_key(unsigned char * rx_secret, 
					  unsigned char * tx_secret,
					  unsigned char * secret) {
	memcpy(rx_secret, secret, SECRET_RTX_LEN);
	memcpy(tx_secret, secret + SECRET_RTX_LEN, SECRET_RTX_LEN);
}

void send_message(message_t *enmsg, secret_t *next_secret,
				  message_t *msg, secret_t *secret) {
	message_t msgn;
	nonce_message(&msgn, next_secret->nonce, msg);

	enmsg->len = MESSAGE_LEN + msgn.len;
	enmsg->data = malloc(sizeof(unsigned char *) * enmsg->len);

	encrypt_message(enmsg, &msgn, secret, next_secret->key);

	free(msgn.data);
}

int receive_message(message_t *msg, secret_t *next_secret,
				  	message_t *enmsg, secret_t *secret) {
	message_t msgn;
	msgn.len = enmsg->len - MESSAGE_LEN;
	msgn.data = malloc(sizeof(unsigned char *) * msgn.len);

	if (decrypt_message(&msgn, enmsg, secret, next_secret->key) != 0) {
		free(msgn.data);
		return 1;
	}

	unnonce_message(msg, next_secret->nonce, &msgn);

	free(msgn.data);
	return 0;
}

void free_bundle(bundle_t *bundle) {
	for (int i = 0; i < bundle->public.opks_number; i++ ) {
		free(bundle->public.onetime_prekeys[i]);
	}
	for (int i = 0; i < bundle->private.opks_number; i++ ) {
		free(bundle->private.onetime_prekeys[i]);
	}
	free(bundle->public.onetime_prekeys);
	free(bundle->private.onetime_prekeys);
	free(bundle->public.opks_ids);
	free(bundle->private.opks_ids);
}

int main() {
    if (sodium_init() == -1) {
        fprintf(stderr, "Libsodium initialization failed\n");
        return 1;
    }
	 if (crypto_aead_aes256gcm_is_available() == 0) {
		abort();
	}

	bundle_t bundle_a;
	create_bundle(&bundle_a);

	bundle_t bundle_b;
	create_bundle(&bundle_b);

	// print_bin_hex(bundle_a.private.indentity, crypto_sign_SECRETKEYBYTES);
	// print_bin_hex(bundle_a.private.signed_prekey, crypto_box_SECRETKEYBYTES);
	// print_bin_hex(bundle_a.private.onetime_prekeys[0], crypto_box_SECRETKEYBYTES);

	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, 
					     bundle_b.public.signed_prekey, 
					     sizeof(bundle_b.public.signed_prekey), 
					  	 bundle_b.private.indentity);
	unsigned char ephemeral_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char secret_key_a[SECRET_LEN];

	request_secret_key(bundle_a.private.indentity,
					   &bundle_b.public,
					   sig,
					   0,
					   ephemeral_pk,
					   secret_key_a);

	unsigned char secret_key_b[SECRET_LEN];
	response_secret_key(&bundle_b.private,
					    0,
					    bundle_a.public.indentity,
					    ephemeral_pk,
					    secret_key_b);


	secret_t secret_a;
	memcpy(secret_a.key, secret_key_a, SECRET_RTX_LEN);
	memcpy(secret_a.nonce, "NONCENONCE__", NONCE_LEN);
	secret_t secret_b;
	memcpy(secret_b.key, secret_key_b, SECRET_RTX_LEN);
	memcpy(secret_b.nonce, "NONCENONCE__", NONCE_LEN);

	// message_t message_a = {
	// 	.data = (unsigned char *)"Hello WORLD",
	// 	.len = 11
	// };

	message_t message_a = {
		.data = (unsigned char *)"Hello WORLD uu",
		.len = 100
	};

	message_t message_en;
	send_message(&message_en, &secret_a, &message_a, &secret_a);

	int status;	
	message_t message_b;
	status = receive_message(&message_b, &secret_b, &message_en, &secret_b);

	printf("STATUS: %d\n", status);
	printf("DECRYPT: %s\n", message_b.data);

 	print_bin_hex(message_en.data, MESSAGE_LEN + 11);

	free(message_en.data);	
	free(message_b.data);
	free_bundle(&bundle_a);	
	free_bundle(&bundle_b);	

    return 0;
}
