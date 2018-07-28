/*******************************************************************************
 * MIT License
 *
 * Copyright (c) 2018 Leonardo Gates
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

class testGenerator {
    /**
     * @constructor
     * @desc Loads required modules for test generation.
     */
    constructor() {
        this.fs = require( 'fs' );
        this.crypto = require( 'crypto' );
        this.discordCrypt = require( '../build/discordCrypt.plugin.js' ).discordCrypt;
        this.discordCrypt_instance = new ( this.discordCrypt )();
        this.cipherModeCount = this.discordCrypt_instance._encryptModes.length;

        this.ciphers = [
            {
                full_name: 'AES-256',
                name: 'aes-256',
                block_size: 16,
                key_size: 32,
                encrypt: this.discordCrypt.__aes256_encrypt,
                decrypt: this.discordCrypt.__aes256_decrypt,
            },
            {
                full_name: 'Camellia-256',
                name: 'camellia-256',
                block_size: 16,
                key_size: 32,
                encrypt: this.discordCrypt.__camellia256_encrypt,
                decrypt: this.discordCrypt.__camellia256_decrypt,
            },
            {
                full_name: 'TripleDES-192',
                name: 'tripledes-192',
                block_size: 8,
                key_size: 24,
                encrypt: this.discordCrypt.__tripledes192_encrypt,
                decrypt: this.discordCrypt.__tripledes192_decrypt,
            },
            {
                full_name: 'IDEA-128',
                name: 'idea-128',
                block_size: 8,
                key_size: 16,
                encrypt: this.discordCrypt.__idea128_encrypt,
                decrypt: this.discordCrypt.__idea128_decrypt,
            },
            {
                full_name: 'Blowfish-512',
                name: 'blowfish-512',
                block_size: 8,
                key_size: 64,
                encrypt: this.discordCrypt.__blowfish512_encrypt,
                decrypt: this.discordCrypt.__blowfish512_decrypt
            }
        ];
        this.block_modes = [
            'cbc',
            'cfb',
            'ofb'
        ];
        this.padding_schemes = [
            'PKC7',
            'ANS2',
            'ISO9',
            'ISO1',
        ];

        this.discordCrypt.__loadLibraries( this.discordCrypt_instance._libraries );
    }

    /**
     * @desc Generates individual tests for each cipher mode and padding scheme.
     * @param {int} num_tests The number of tests to generate.
     * @param {Array<Object>} unit_tests The output array to store the generated tests.
     * @param {int} i The index of ciphers used for this test.
     * @param {int} j The block operation mode of the ciphers.
     * @param {int} k The padding scheme for the ciphers.
     */
    addCipherTest( num_tests = 25, unit_tests, i, j, k ) {
        /* Loop for the number of tests desired. */
        for ( let l = 0; l < num_tests; l++ ) {
            /* Generate random plaintext. */
            let plaintext = this.crypto.randomBytes( ( this.ciphers[ i ].key_size * ( l + 1 ) ) + ( l + k + i ) );

            /* Generate a random key and one-time salt. */
            let key = this.crypto.randomBytes( this.ciphers[ i ].key_size );
            let salt = this.crypto.randomBytes( 8 );

            /* Perform a round of encryption. */
            let ciphertext = this.ciphers[ i ].encrypt(
                plaintext,
                key,
                unit_tests[ i ].tests[ j ][ k ].mode,
                unit_tests[ i ].tests[ j ][ k ].scheme,
                true,
                false,
                salt
            );

            /* Perform a round of decryption. */
            let _plaintext = this.ciphers[ i ].decrypt(
                ciphertext,
                key,
                unit_tests[ i ].tests[ j ][ k ].mode,
                unit_tests[ i ].tests[ j ][ k ].scheme,
                'hex',
                true
            );

            /* Make sure that the plaintext generated matches the decrypted value. */
            if ( _plaintext !== plaintext.toString( 'hex' ) ) {
                l--;
                console.log( `Invalid test generated for ${this.ciphers[ i ].name}.` );
                continue;
            }

            /* Store the test result. */
            unit_tests[ i ].tests[ j ][ k ].r[ l ] = {};

            unit_tests[ i ].tests[ j ][ k ].r[ l ].plaintext = plaintext.toString( 'hex' );
            unit_tests[ i ].tests[ j ][ k ].r[ l ].ciphertext = ciphertext;

            unit_tests[ i ].tests[ j ][ k ].r[ l ].key = key.toString( 'hex' );
            unit_tests[ i ].tests[ j ][ k ].r[ l ].salt = salt.toString( 'hex' );
        }
    }

    /**
     * @desc Generates cipher test vectors.
     * @param {int} num_tests The number of tests to generate PER cipher-combo PER block mode PER padding scheme.
     * @param {string} output_path The output path of the JSON file containing the generated test vectors.
     */
    generateCipherTests( num_tests = 25, output_path = './tests/vectors/cipher-test-vectors.json' ) {

        let unit_tests = [];

        for ( let i = 0; i < this.ciphers.length; i++ ) {

            unit_tests[ i ] = {};

            unit_tests[ i ].full_name = this.ciphers[ i ].full_name;
            unit_tests[ i ].name = this.ciphers[ i ].name;

            unit_tests[ i ].tests = [];

            for ( let j = 0; j < this.block_modes.length; j++ ) {

                unit_tests[ i ].tests[ j ] = [];

                for ( let k = 0; k < this.padding_schemes.length; k++ ) {

                    unit_tests[ i ].tests[ j ][ k ] = {};
                    unit_tests[ i ].tests[ j ][ k ].mode = this.block_modes[ j ];
                    unit_tests[ i ].tests[ j ][ k ].scheme = this.padding_schemes[ k ];
                    unit_tests[ i ].tests[ j ][ k ].r = [];

                    this.addCipherTest( num_tests, unit_tests, i, j, k );
                }
            }
        }

        /* Add AES-GCM tests. */
        let aes_gcm = {};

        /* Keep to the standard format above. */
        aes_gcm.full_name = 'AES-256-GCM';
        aes_gcm.name = 'aes-256-gcm';
        aes_gcm.tests = [];

        /* Since GCM is the only mode tested here, use only 1 entry. */
        aes_gcm.tests[ 0 ] = [];

        /* Loop over all padding schemes. */
        for ( let k = 0; k < this.padding_schemes.length; k++ ) {
            aes_gcm.tests[ 0 ][ k ] = {};
            aes_gcm.tests[ 0 ][ k ].mode = 'gcm';
            aes_gcm.tests[ 0 ][ k ].scheme = this.padding_schemes[ k ];

            aes_gcm.tests[ 0 ][ k ].r = [];

            /* Generate each test. */
            for ( let l = 0; l < num_tests; l++ ) {
                /* Generate random plaintext. */
                let plaintext = this.crypto.randomBytes( ( 32 * ( l + 1 ) ) + ( l + k + this.ciphers.length ) );

                /* Generate a random key and one-time salt. */
                let key = this.crypto.randomBytes( 32 );
                let salt = this.crypto.randomBytes( 8 );

                /* Perform a round of encryption. */
                let ciphertext = this.discordCrypt.__aes256_encrypt_gcm(
                    plaintext,
                    key,
                    this.padding_schemes[ k ],
                    true,
                    false,
                    undefined,
                    salt
                );

                /* Perform a round of decryption. */
                let _plaintext = this.discordCrypt.__aes256_decrypt_gcm(
                    ciphertext,
                    key,
                    this.padding_schemes[ k ],
                    'hex',
                    true
                );

                /* Make sure that the plaintext generated matches the decrypted value. */
                if ( _plaintext !== plaintext.toString( 'hex' ) ) {
                    l--;
                    console.log( `Invalid test generated for ${this.ciphers[ i ].name}.` );
                    continue;
                }

                /* Store the test result. */
                aes_gcm.tests[ 0 ][ k ].r[ l ] = {};

                aes_gcm.tests[ 0 ][ k ].r[ l ].plaintext = plaintext.toString( 'hex' );
                aes_gcm.tests[ 0 ][ k ].r[ l ].ciphertext = ciphertext;

                aes_gcm.tests[ 0 ][ k ].r[ l ].key = key.toString( 'hex' );
                aes_gcm.tests[ 0 ][ k ].r[ l ].salt = salt.toString( 'hex' );
            }
        }

        unit_tests[ this.ciphers.length ] = aes_gcm;

        this.fs.writeFileSync( output_path, JSON.stringify( unit_tests, undefined, ' ' ) );
    }

    /**
     * @desc Generate hash test vectors.
     * @param {int} num_tests The number of tests to generate.
     * @param {string} output_path The output path of the JSON file containing the generated test vectors.
     */
    generateHashTests( num_tests = 25,  output_path = './tests/vectors/hash-test-vectors.json' ) {
        let unit_tests = [];
        const hash_list = [
            {
                name: 'sha1',
                length: 20,
                hash: this.discordCrypt.__sha160,
            },
            {
                name: 'sha256',
                length: 32,
                hash: this.discordCrypt.__sha256,
            },
            {
                name: 'sha512',
                length: 64,
                hash: this.discordCrypt.__sha512,
            },
            {
                name: 'sha512_128',
                length: 16,
                hash: this.discordCrypt.__sha512_128,
            },
            {
                name: 'whirlpool',
                length: 64,
                hash: this.discordCrypt.__whirlpool,
            },
            {
                name: 'whirlpool64',
                length: 8,
                hash: this.discordCrypt.__whirlpool64,
            },
            {
                name: 'whirlpool192',
                length: 24,
                hash: this.discordCrypt.__whirlpool192,
            }
        ];

        for ( let i = 0; i < hash_list.length; i++ ) {
            unit_tests[ i ] = {};

            unit_tests[ i ].name = hash_list[ i ].name;
            unit_tests[ i ].length = hash_list[ i ].length;
            unit_tests[ i ].tests = [];

            for ( let j = 0; j < num_tests; j++ ) {
                let input = this.crypto.randomBytes( hash_list[ i ].length * ( j + 1 ) + j );

                unit_tests[ i ].tests[ j ] = {};
                unit_tests[ i ].tests[ j ].input = input.toString( 'hex' );
                unit_tests[ i ].tests[ j ].output = hash_list[ i ].hash( input, true );
            }
        }

        this.fs.writeFileSync( output_path, JSON.stringify( unit_tests, undefined, ' ' ) );
    }

    /**
     * @desc Generate HMAC test vectors.
     * @param {int} num_tests The number of tests to generate.
     * @param {string} output_path The output path of the JSON file containing the generated test vectors.
     */
    generateHMACTests( num_tests = 25,  output_path = './tests/vectors/hmac-test-vectors.json' ) {
        let unit_tests = [];
        const hmac_list = [
            {
                name: 'hmac_sha256',
                length: 32,
                hash: this.discordCrypt.__hmac_sha256,
            },
            {
                name: 'hmac_sha512',
                length: 64,
                hash: this.discordCrypt.__hmac_sha512,
            },
            {
                name: 'hmac_whirlpool',
                length: 64,
                hash: this.discordCrypt.__hmac_whirlpool,
            }
        ];

        for ( let i = 0; i < hmac_list.length; i++ ) {
            unit_tests[ i ] = {};

            unit_tests[ i ].name = hmac_list[ i ].name;
            unit_tests[ i ].length = hmac_list[ i ].length;
            unit_tests[ i ].tests = [];

            for ( let j = 0; j < num_tests; j++ ) {
                let input = this.crypto.randomBytes( hmac_list[ i ].length * ( j + 1 ) + j );
                let salt = this.crypto.randomBytes( hmac_list[ i ].length * ( j + 1 ) + j );

                unit_tests[ i ].tests[ j ] = {};
                unit_tests[ i ].tests[ j ].input = input.toString( 'hex' );
                unit_tests[ i ].tests[ j ].salt = salt.toString( 'hex' );
                unit_tests[ i ].tests[ j ].output = hmac_list[ i ].hash( input, salt, true );
            }
        }

        this.fs.writeFileSync( output_path, JSON.stringify( unit_tests, undefined, ' ' ) );
    }

    /**
     * @desc Generate symmetric encryption & decryption tests which includes encoding.
     * @param {int} num_tests The number of tests to generate.
     * @param {string} output_path The output path of the JSON file containing the generated test vectors.
     */
    generateFullEncryptionTests( num_tests = 5, output_path = './tests/vectors/encode-test-vectors.json' ) {
        let unit_tests = [];

        /* Loop over each dual-encryption type. */
        for ( let i = 0; i < this.cipherModeCount; i++ ) {
            unit_tests[ i ] = [];

            /* Loop over every block encryption mode. */
            for ( let j = 0; j < this.block_modes.length; j++ ) {
                unit_tests[ i ][ j ] = [];

                /* Loop over every padding scheme.*/
                for ( let k = 0; k < this.padding_schemes.length; k++ ) {
                    unit_tests[ i ][ j ][ k ] = {};

                    unit_tests[ i ][ j ][ k ].mode = this.block_modes[ j ];
                    unit_tests[ i ][ j ][ k ].scheme = this.padding_schemes[ k ];
                    unit_tests[ i ][ j ][ k ].r = [];

                    /* Generate each test. */
                    for ( let l = 0; l < num_tests; l++ ) {
                        /* Get some random values. */
                        let len = parseInt( this.crypto.randomBytes( 1 ).toString( 'hex' ), 16 ) + 32 + i + j + k + l,
                            primary = this.crypto.randomBytes( parseInt( len / 2 ) ),
                            secondary = this.crypto.randomBytes( parseInt( len / 3 ) ),
                            plaintext = this.crypto.randomBytes( len + ( l % 5 ? l + 33 : k + 11 ) );

                        /* Store the test output. */
                        unit_tests[ i ][ j ][ k ].r[ l ] = {};
                        unit_tests[ i ][ j ][ k ].r[ l ].primary_key = primary.toString( 'hex' );
                        unit_tests[ i ][ j ][ k ].r[ l ].secondary_key = secondary.toString( 'hex' );
                        unit_tests[ i ][ j ][ k ].r[ l ].plaintext = plaintext.toString( 'hex' );
                        unit_tests[ i ][ j ][ k ].r[ l ].ciphertext = this.discordCrypt.__symmetricEncrypt(
                            plaintext,
                            primary,
                            secondary,
                            i,
                            this.block_modes[ j ],
                            this.padding_schemes[ k ],
                            true
                        );
                    }
                }
            }
        }

        this.fs.writeFileSync( output_path, JSON.stringify( unit_tests, undefined, ' ' ) );
    }
}

module.exports = { testGenerator };
