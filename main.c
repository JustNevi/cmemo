#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>

#define ONETIME_PREKEYS_NUMBER 100 

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
	crypto_sign_ed25519_sk_to_curve25519(indentity_x_sk, indentity_sk);

	unsigned char ephemeral_sk[crypto_box_SECRETKEYBYTES];
	keypair_t ephemeral_pair = {
		.public = ephemeral_pk,
		.private = ephemeral_sk
	};
	if (generate_exchange_keypair(&ephemeral_pair) != 0) {
		fprintf(stderr, "Failed to generate ephemeral keypair.\n");
		return 2;
	}

	unsigned char *onetime_prekey = get_opk_by_id(bundle->onetime_prekeys,
											      bundle->opks_number,
												  bundle->opks_ids,
											   	  opk_id);
	if (onetime_prekey == NULL) {
		fprintf(stderr, "Not valid onetime prekey id.\n");
		return 3;
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

	print_bin_hex(dh_concat, sizeof(dh_concat));
	printf("%s", secret_key);

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

	print_bin_hex(dh_concat, sizeof(dh_concat));
	printf("%s", secret_key);

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
	unsigned char secret_key_a[crypto_generichash_BYTES];

	request_secret_key(bundle_a.private.indentity,
					   &bundle_b.public,
					   sig,
					   0,
					   ephemeral_pk,
					   secret_key_a);

	unsigned char secret_key_b[crypto_generichash_BYTES];
	response_secret_key(&bundle_b.private,
					    0,
					    bundle_a.public.indentity,
					    ephemeral_pk,
					    secret_key_b);

	free_bundle(&bundle_a);	
	free_bundle(&bundle_b);	

    return 0;
}
