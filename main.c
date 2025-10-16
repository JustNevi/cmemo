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

void concat_array(unsigned char **array, int alen, 
				  unsigned char *concat, int clen) {
	for (int i = 0; i < alen; i++) {
		memcpy(concat + clen * i, array[i], clen);
	}   
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

	unsigned char dh1[crypto_scalarmult_BYTES];
	unsigned char dh2[crypto_scalarmult_BYTES];
	unsigned char dh3[crypto_scalarmult_BYTES];
	unsigned char dh4[crypto_scalarmult_BYTES];

	if (crypto_scalarmult(dh1,
					   	  indentity_x_sk, 
					      bundle->signed_prekey) != 0) {
		fprintf(stderr, "Failed to scalarmult DH1.\n");
		return 3;
	}
	if (crypto_scalarmult(dh2,
					   	  ephemeral_sk, 
					      bundle->indentity) != 0) {
		fprintf(stderr, "Failed to scalarmult DH2.\n");
		return 4;
	}
	if (crypto_scalarmult(dh3,
					   	  ephemeral_sk, 
					      bundle->signed_prekey) != 0) {
		fprintf(stderr, "Failed to scalarmult DH3.\n");
		return 5;
	}

	int opk_index = get_index_from_ids(opk_id,
									   bundle->opks_ids,
									   bundle->opks_number);
	if (opk_index == -1) {
		fprintf(stderr, "Not valid onetime prekey id.\n");
		return 6;
	}

	unsigned char *onetime_prekey = bundle->onetime_prekeys[opk_index];
	if (crypto_scalarmult(dh4,
					   	  ephemeral_sk, 
					      onetime_prekey) != 0) {
		fprintf(stderr, "Failed to scalarmult DH4.\n");
		return 6;
	}

	unsigned char dh_concat[crypto_scalarmult_BYTES * 4];
	unsigned char *dhs[] = {dh1, dh2, dh3, dh4};
	concat_array(dhs, 4, dh_concat, crypto_scalarmult_BYTES);

	print_bin_hex(dh_concat, sizeof(dh_concat));

	return 0;
}

int response_secret_key(bundle_private_t *bundle,
					   	 int opk_id,
						 unsigned char *indentity_pk,
					   	 unsigned char *ephemeral_pk,
					   	 unsigned char *secret_key) {

	unsigned char indentity_x_pk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_pk_to_curve25519(indentity_x_pk, indentity_pk);

	unsigned char dh1[crypto_scalarmult_BYTES];
	unsigned char dh2[crypto_scalarmult_BYTES];
	unsigned char dh3[crypto_scalarmult_BYTES];
	unsigned char dh4[crypto_scalarmult_BYTES];

	if (crypto_scalarmult(dh1,
					   	  bundle->signed_prekey, 
					      indentity_x_pk) != 0) {
		fprintf(stderr, "Failed to scalarmult DH1.\n");
		return 3;
	}
	if (crypto_scalarmult(dh2,
						  bundle->indentity,
					   	  ephemeral_pk) != 0) {
		fprintf(stderr, "Failed to scalarmult DH2.\n");
		return 4;
	}
	if (crypto_scalarmult(dh3,
						  bundle->signed_prekey,
					   	  ephemeral_pk) != 0) {
		fprintf(stderr, "Failed to scalarmult DH3.\n");
		return 5;
	}

	int opk_index = get_index_from_ids(opk_id,
									   bundle->opks_ids,
									   bundle->opks_number);
	if (opk_index == -1) {
		fprintf(stderr, "Not valid onetime prekey id.\n");
		return 6;
	}

	unsigned char *onetime_prekey = bundle->onetime_prekeys[opk_index];
	if (crypto_scalarmult(dh4,
					   	  onetime_prekey, 
					      ephemeral_pk) != 0) {
		fprintf(stderr, "Failed to scalarmult DH4.\n");
		return 6;
	}

	unsigned char dh_concat[crypto_scalarmult_BYTES * 4];
	unsigned char *dhs[] = {dh1, dh2, dh3, dh4};
	concat_array(dhs, 4, dh_concat, crypto_scalarmult_BYTES);

	print_bin_hex(dh_concat, sizeof(dh_concat));

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
	// print_bin_hex(bundle_a.private.indentity, crypto_sign_PUBLICKEYBYTES);
	// print_bin_hex(bundle_a.private.signed_prekey, crypto_box_PUBLICKEYBYTES);
	// print_bin_hex(bundle_a.private.onetime_prekeys[0], crypto_box_PUBLICKEYBYTES);
	// print_bin_hex(bundle_a.public.signed_prekey, crypto_box_PUBLICKEYBYTES);

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
