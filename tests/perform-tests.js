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

class testRunner {
    /**
     * @desc Loads the dependency _libraries and discordCrypt.
     * @constructor
     */
    constructor() {

        /**
         * @private
         * @desc Symmetric block modes of operation.
         * @type {string[]}
         */
        this.ENCRYPT_BLOCK_MODES = [
            'CBC', /* Cipher Block-Chaining */
            'CFB', /* Cipher Feedback Mode */
            'OFB', /* Output Feedback Mode */
        ];

        /**
         * @private
         * @desc Shorthand padding modes for block ciphers referred to in the code.
         * @type {string[]}
         */
        this.PADDING_SCHEMES = [
            'PKC7', /* PKCS #7 */
            'ANS2', /* ANSI X.923 */
            'ISO1', /* ISO-10126 */
            'ISO9', /* ISO-97972 */
        ];

        /* Cache required modules. */
        this.process = require( 'process' );
        this.nodeunit = require( 'nodeunit' );
        this.child_process = require( 'child_process' );

        /* Perform a build. */
        this.child_process.fork(
            this.process.argv[ 0 ],
            {
                execArgv: [ 'src/build.js', '-o', 'build' ],
                cwd: this.process.cwd(),
                env: Object.create( this.process.env )
            }
        ).on( 'exit', () => {

            /* Import the built file. */
            this.discordCrypt = require( '../build/discordCrypt.plugin.js' ).discordCrypt;

            /* Create an instance. */
            this.discordCrypt_instance = new ( this.discordCrypt )();

            /* Load all _libraries required. */
            this.discordCrypt.__loadLibraries( this.discordCrypt_instance._libraries );

            /* Run the tests. */
            this.run();

        } );
    }

    /**
     * @desc Runs tests based on command line parameters.
     */
    run() {
        /* Prepare the unit tests. */
        let unit_tests = {};

        /* Handle which tests to run. */
        try {
            switch ( process.argv[ 2 ].toLowerCase() ) {
            case 'scrypt':
                /* Run Scrypt tests. */
                this.addScryptTests( unit_tests );
                break;
            case 'pbkdf2':
                /* Run PBKDF2 tests. */
                this.addPBKDF2Tests( unit_tests );
                break;
            case 'hash':
                /* Run hash tests. */
                this.addHashTests( unit_tests );
                break;
            case 'hmac':
                /* Run HMAC tests. */
                this.addHMACTests( unit_tests );
                break;
            case 'cipher':
                /* Run cipher tests. */
                this.addCipherTests( unit_tests, process.argv.length >= 4 ? process.argv[ 3 ] : '' );
                break;
            case 'general':
                /* Run generic tests. */
                this.addGenericTests( unit_tests );
                break;
            case 'exchange':
                /* Run key exchange tests. */
                this.addDiffieHellmanTests( unit_tests );
                break;
            case 'encoding':
                /* Run encoding tests. */
                this.addEncodingTests( unit_tests );
                break;
            case 'coverage':
                /* Run generic tests. */
                this.addGenericTests( unit_tests );

                /* Run one Scrypt test. */
                this.addScryptTests( unit_tests, true );

                /* Run a single Hash/PBKDF2 test of each type. */
                this.addPBKDF2Tests( unit_tests, true );

                /* Run hash tests. */
                this.addHashTests( unit_tests, true );

                /* Run HMAC tests. */
                this.addHMACTests( unit_tests, true );

                /* Run only a single test of each cipher type. */
                this.addCipherTests( unit_tests, undefined, true );

                /* Run encoding tests. */
                this.addEncodingTests( unit_tests, true );

                /* Run key exchange tests once for every key length. */
                this.addDiffieHellmanTests( unit_tests, true );
                break;
            default:
                throw 'Executing all tests.';
            }
        }
        catch ( e ) {

            /* Run generic tests. */
            this.addGenericTests( unit_tests );

            /* Run Scrypt tests. */
            this.addScryptTests( unit_tests );

            /* Run Hash/PBKDF2 tests. */
            this.addPBKDF2Tests( unit_tests );

            /* Run hash tests. */
            this.addHashTests( unit_tests );

            /* Run HMAC tests. */
            this.addHMACTests( unit_tests );

            /* Run cipher tests. */
            this.addCipherTests( unit_tests );

            /* Run encoding tests. */
            this.addEncodingTests( unit_tests );

            /* Run key exchange tests. */
            this.addDiffieHellmanTests( unit_tests );
        }

        /* Actually run all the tests. */
        this.nodeunit.reporters.default.run( unit_tests );
    }

    /**
     * @desc Adds Scrypt() based tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addScryptTests( unit_tests, coverage ) {
        const vectors = require( './vectors/scrypt-test-vectors' );

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_scrypt = {};

        /* Loop over all tests. */
        let num_tests = coverage === undefined ? vectors.length : 1;
        for ( let i = 0; i < num_tests; i++ ) {
            let v = vectors[ i ],
                k = `Test #${Object.keys( unit_tests.discordCrypt_scrypt ).length + 1}: ` +
                    `[ N: ${v.N} r: ${v.r} p: ${v.p} ]`;

            /* Create a function callback for this test name. */
            unit_tests.discordCrypt_scrypt[ k ] = ( ut ) => {
                /* Convert the password and salt to Buffer objects. */
                let password = new Buffer( v.password, 'hex' );
                let salt = new Buffer( v.salt, 'hex' );

                /* Save the key. */
                let derivedKey = v.derivedKey;

                /* Passed from the loaded class file. */
                this.discordCrypt.__scrypt( password, salt, v.dkLen, v.N, v.r, v.p, ( error, progress, key ) => {
                    /* On errors, let the user know. */
                    if ( error ) {
                        this.discordCrypt.log( error );
                        return;
                    }

                    /* Once the key has been calculated, check it. */
                    if ( key ) {
                        ut.equal( derivedKey, key.toString( 'hex' ), 'Derived key check failed.' );
                        ut.done();
                    }
                } );
            };
        }
    }

    /**
     * @desc Adds PBKDF2() based tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addPBKDF2Tests( unit_tests, coverage ) {

        /* Load the test units. */
        const hash_vectors = require( './vectors/pbkdf2-test-vectors.json' );
        const hash_list = [
            {
                name: 'sha1',
                length: 20,
                fn: this.discordCrypt.__pbkdf2_sha160
            },
            {
                name: 'sha256',
                length: 32,
                fn: this.discordCrypt.__pbkdf2_sha256
            },
            {
                name: 'sha512',
                length: 64,
                fn: this.discordCrypt.__pbkdf2_sha512
            },
            {
                name: 'whirlpool',
                length: 64,
                fn: this.discordCrypt.__pbkdf2_whirlpool
            }
        ];

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_pbkdf2 = {};

        /**
         * @desc Adds the given PBKDF2 class of tests to the array.
         * @param {testRunner} instance A reference to the current implementation of the test runner.
         * @param {string} name The name of the hash class to run.
         * @param {int} hash_size The size of the hash generated in bytes.
         * @param {function} fn The PBKDF2 function for this hash.
         * @param {Array} v The array of test vectors to run for this hash function.
         */
        function prepare_run( instance, name, hash_size, fn, v ) {
            for ( let i = 0; i < ( coverage === undefined ? v.length : 1 ); i++ ) {
                let format =
                    `${name}: Test #${Object.keys( unit_tests.discordCrypt_pbkdf2 ).length}`;

                unit_tests.discordCrypt_pbkdf2[ format ] = ( ut ) => {
                    let hash = fn(
                        new Buffer( v[ i ].password, 'utf8' ),
                        new Buffer( v[ i ].salt, 'utf8' ),
                        true,
                        undefined,
                        undefined,
                        hash_size,
                        v[ i ].iterations
                    );

                    ut.equal( hash, v[ i ][ name ], `Hash mismatch for ${name}.` );
                    ut.done();
                };
            }
        }

        /* Register all tests. */
        for ( let i = 0; i < hash_list.length; i++ )
            prepare_run( this, hash_list[ i ].name, hash_list[ i ].length, hash_list[ i ].fn, hash_vectors );
    }

    /**
     * @desc Adds hash based tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addHashTests( unit_tests, coverage ) {

        /* Load the test units. */
        const hash_vectors = require( './vectors/hash-test-vectors.json' );
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

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_hash = {};

        /**
         * @desc Finds the hash algorithm used for the given hash name.
         * @param {string} name The name of the hash algorithm.
         * @returns {function} The hash function used for this hash name.
         */
        function find_hash_algorithm( name ) {
            for ( let i = 0; i < hash_list.length; i++ )
                if ( name == hash_list[ i ].name )
                    return hash_list[ i ].hash;
            return null;
        }

        /* Register all tests types. */
        for ( let i = 0; i < hash_vectors.length; i++ ) {
            let name = hash_vectors[ i ].name;
            let hash_algorithm = find_hash_algorithm( name );
            let v = hash_vectors[ i ].tests;

            /* Run each test. */
            for ( let j = 0; j < ( coverage === undefined ? v.length : 1 ); j++ ) {
                let format =
                    `${name}: Test #${Object.keys( unit_tests.discordCrypt_hash ).length}`;

                unit_tests.discordCrypt_hash[ format ] = ( ut ) => {
                    let hash = hash_algorithm(
                        new Buffer( v[ j ].input, 'hex' ),
                        true,
                    );

                    ut.equal( hash, v[ j ].output, `Hash mismatch for ${name}.` );
                    ut.done();
                };
            }
        }
    }

    /**
     * @desc Adds HMAC based tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addHMACTests( unit_tests, coverage ) {

        /* Load the test units. */
        const hash_vectors = require( './vectors/hmac-test-vectors.json' );
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

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_hmac = {};

        /**
         * @desc Finds the HMAC algorithm used for the given hash name.
         * @param {string} name The name of the hash algorithm.
         * @returns {function} The hash function used for this hash name.
         */
        function find_hmac_algorithm( name ) {
            for ( let i = 0; i < hmac_list.length; i++ )
                if ( name == hmac_list[ i ].name )
                    return hmac_list[ i ].hash;
            return null;
        }

        /* Register all tests types. */
        for ( let i = 0; i < hash_vectors.length; i++ ) {
            let name = hash_vectors[ i ].name;
            let hash_algorithm = find_hmac_algorithm( name );
            let v = hash_vectors[ i ].tests;

            /* Run each test. */
            for ( let j = 0; j < ( coverage === undefined ? v.length : 1 ); j++ ) {
                let format =
                    `${name}: Test #${Object.keys( unit_tests.discordCrypt_hmac ).length}`;

                unit_tests.discordCrypt_hmac[ format ] = ( ut ) => {
                    let hash = hash_algorithm(
                        new Buffer( v[ j ].input, 'hex' ),
                        new Buffer( v[ j ].salt, 'hex' ),
                        true,
                    );

                    ut.equal( hash, v[ j ].output, `Hash mismatch for ${name}.` );
                    ut.done();
                };
            }
        }
    }

    /**
     * @desc Adds cipher based tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {string} preferred_cipher If specified, only the tests for this cipher is added.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addCipherTests( unit_tests, preferred_cipher = undefined, coverage ) {
        const vectors = require( './vectors/cipher-test-vectors.json' );

        /**
         * @desc Locates the given array containing the target's test vectors.
         * @param {Array} list The list of test vectors.
         * @param {string} name The name of the cipher.
         * @returns {Object} Returns the cipher test vector object.
         */
        function locateTestVector( list, name ) {
            for ( let i = 0; i < list.length; i++ ) {
                if ( list[ i ].full_name.toLowerCase() === name.toLowerCase() )
                    return list[ i ];
            }

            return null;
        }

        /**
         * @desc Adds a cipher test list to be checked.
         * @param {Array} unit_tests An array of unit tests to run.
         * @param {string} cipher_name If specified, only the tests for this cipher is added.
         * @param {Array} test_vectors The full array of test vectors for this cipher.
         * @param {function} encrypt The encryption function for this cipher.
         * @param {function} decrypt The decryption function for this cipher.
         */
        function addCipherTest( unit_tests, cipher_name, test_vectors, encrypt, decrypt ) {
            /* Loop over each individual test. */
            for ( let i = 0; i < test_vectors.length; i++ ) {
                /* Loop over the block mode and padding scheme array. */
                for ( let j = 0; j < test_vectors[ i ].length; j++ ) {

                    /* Backup. */
                    let mode = test_vectors[ i ][ j ].mode;
                    let scheme = test_vectors[ i ][ j ].scheme;

                    /* Save this so future changes are easier. */
                    let test_name = `discordCrypt-${cipher_name}-${mode.toUpperCase()}-${scheme.toUpperCase()}`;

                    /* Create the test unit. */
                    unit_tests[ test_name ] = {};

                    /* Loop over each individual unit test. */
                    for ( let k = 0; k < ( coverage === undefined ? test_vectors[ i ][ j ].r.length : 1 ); k++ ) {
                        /* Convert the target strings from hex format to Buffer objects. */
                        let plaintext = new Buffer( test_vectors[ i ][ j ].r[ k ].plaintext, 'hex' );
                        let ciphertext = new Buffer( test_vectors[ i ][ j ].r[ k ].ciphertext, 'hex' );

                        /* Extract the hex key and salts used. */
                        let key = new Buffer( test_vectors[ i ][ j ].r[ k ].key, 'hex' );
                        let salt = new Buffer( test_vectors[ i ][ j ].r[ k ].salt, 'hex' );

                        /* Backup test ID. */
                        let test_id = `Test #${k + 1}`;

                        /* Create the test callback */
                        unit_tests[ test_name ][ test_id ] =
                            ( ut ) => {
                                let _plaintext, _ciphertext;

                                if ( mode !== 'gcm' )
                                /* Calculate the plaintext by doing a decryption cycle. */
                                    _plaintext = decrypt( ciphertext, key, mode, scheme, 'hex' );
                                else
                                    _plaintext = decrypt( ciphertext, key, scheme, 'hex' );

                                /* Check if they match. */
                                ut.equal( _plaintext, test_vectors[ i ][ j ].r[ k ].plaintext, 'Mismatched plaintext' );

                                /* ISO-10126 uses random padding bytes which we can't predict. */
                                /* As a result, we only test ciphertext equality in padding schemes that don't do this.
                                */
                                if ( scheme.toLowerCase() !== 'iso1' ) {
                                    if ( mode !== 'gcm' )
                                    /* Perform an encryption routine with the predefined key and KDF salt. */
                                        _ciphertext = encrypt( plaintext, key, mode, scheme, true, false, salt );
                                    else
                                    /* Perform an encryption routine with the predefined key and KDF salt. */
                                        _ciphertext = encrypt( plaintext, key, scheme, true, false, undefined, salt );

                                    /* Check if the plaintext and ciphertext calculate match the expected output. */
                                    ut.equal(
                                        _ciphertext, test_vectors[ i ][ j ].r[ k ].ciphertext,
                                        'Mismatched ciphertext'
                                    );
                                }
                                else {
                                    if ( mode !== 'gcm' ) {
                                        /* Here, we simply test if the encryption validates. */
                                        _ciphertext = new Buffer(
                                            encrypt( plaintext, key, mode, scheme, true, false, salt ),
                                            'hex'
                                        );

                                        /* Then we decrypt the ciphertext. */
                                        _plaintext = decrypt( _ciphertext, key, mode, scheme, 'hex' );
                                    }
                                    else {
                                        /* Here, we simply test if the encryption validates. */
                                        _ciphertext = new Buffer(
                                            encrypt( plaintext, key, scheme, true, false, undefined, salt ),
                                            'hex'
                                        );

                                        /* Then we decrypt the ciphertext. */
                                        _plaintext = decrypt( _ciphertext, key, scheme, 'hex' );
                                    }

                                    /* Check if the newly decrypted plaintext is valid. */
                                    ut.equal(
                                        _plaintext, test_vectors[ i ][ j ].r[ k ].plaintext,
                                        'Encryption failure'
                                    );
                                }

                                /* Finish the test. */
                                ut.done();
                            };
                    }
                }
            }

        }

        /* Quick sanity check. */
        if ( typeof preferred_cipher !== 'string' )
            preferred_cipher = 'Running all cipher tests';

        /* Fetch all test vectors. */
        let aes_vectors = locateTestVector( vectors, 'aes-256' ),
            aes_gcm_vectors = locateTestVector( vectors, 'aes-256-gcm' ),
            camellia_vectors = locateTestVector( vectors, 'camellia-256' ),
            tripledes_vectors = locateTestVector( vectors, 'tripledes-192' ),
            idea_vectors = locateTestVector( vectors, 'idea-128' ),
            blowfish_vectors = locateTestVector( vectors, 'blowfish-512' );

        /* Locate the desired cipher. Tons of redundant code here :) */
        switch ( preferred_cipher ) {
        case 'aes':
        case 'aes256':
        case 'aes-256':
            addCipherTest(
                unit_tests,
                aes_vectors.full_name,
                aes_vectors.tests,
                this.discordCrypt.__aes256_encrypt,
                this.discordCrypt.__aes256_decrypt
            );
            addCipherTest(
                unit_tests,
                aes_gcm_vectors.full_name,
                aes_gcm_vectors.tests,
                this.discordCrypt.__aes256_encrypt_gcm,
                this.discordCrypt.__aes256_decrypt_gcm
            );
            break;
        case 'camellia':
        case 'camellia256':
        case 'camellia-256':
            addCipherTest(
                unit_tests,
                camellia_vectors.full_name,
                camellia_vectors.tests,
                this.discordCrypt.__camellia256_encrypt,
                this.discordCrypt.__camellia256_decrypt
            );
            break;
        case 'tripledes':
        case 'tripledes192':
        case 'tripledes-192':
            addCipherTest(
                unit_tests,
                tripledes_vectors.full_name,
                tripledes_vectors.tests,
                this.discordCrypt.__tripledes192_encrypt,
                this.discordCrypt.__tripledes192_decrypt
            );
            break;
        case 'idea':
        case 'idea128':
        case 'idea-128':
            addCipherTest(
                unit_tests,
                idea_vectors.full_name,
                idea_vectors.tests,
                this.discordCrypt.__idea128_encrypt,
                this.discordCrypt.__idea128_decrypt
            );
            break;
        case 'blowfish':
        case 'blowfish512':
        case 'blowfish-512':
            addCipherTest(
                unit_tests,
                blowfish_vectors.full_name,
                blowfish_vectors.tests,
                this.discordCrypt.__blowfish512_encrypt,
                this.discordCrypt.__blowfish512_decrypt
            );
            break;
        default:
            addCipherTest(
                unit_tests,
                aes_vectors.full_name,
                aes_vectors.tests,
                this.discordCrypt.__aes256_encrypt,
                this.discordCrypt.__aes256_decrypt
            );
            addCipherTest(
                unit_tests,
                aes_gcm_vectors.full_name,
                aes_gcm_vectors.tests,
                this.discordCrypt.__aes256_encrypt_gcm,
                this.discordCrypt.__aes256_decrypt_gcm
            );
            addCipherTest(
                unit_tests,
                camellia_vectors.full_name,
                camellia_vectors.tests,
                this.discordCrypt.__camellia256_encrypt,
                this.discordCrypt.__camellia256_decrypt
            );
            addCipherTest(
                unit_tests,
                tripledes_vectors.full_name,
                tripledes_vectors.tests,
                this.discordCrypt.__tripledes192_encrypt,
                this.discordCrypt.__tripledes192_decrypt
            );
            addCipherTest(
                unit_tests,
                idea_vectors.full_name,
                idea_vectors.tests,
                this.discordCrypt.__idea128_encrypt,
                this.discordCrypt.__idea128_decrypt
            );
            addCipherTest(
                unit_tests,
                blowfish_vectors.full_name,
                blowfish_vectors.tests,
                this.discordCrypt.__blowfish512_encrypt,
                this.discordCrypt.__blowfish512_decrypt
            );
            break;
        }
    }

    /**
     * @desc Adds full encryption encoding tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addEncodingTests( unit_tests, coverage ) {
        const vectors = require( './vectors/encode-test-vectors.json' );

        /* Loop over every dual-encryption combination. */
        for ( let i = 0; i < vectors.length; i++ ) {
            let cipher_index = i;

            /* Loop over every block mode. */
            for ( let j = 0; j < vectors[ i ].length; j++ ) {
                /* Loop over every padding mode. */
                for ( let k = 0; k < vectors[ i ][ j ].length; k++ ) {

                    /* Get the block operation mode and padding scheme used. */
                    let block_mode = vectors[ i ][ j ][ k ].mode;
                    let padding_scheme = vectors[ i ][ j ][ k ].scheme;

                    /* Convert the cipher index to a string for logging. */
                    let cipher_string =
                        `${this.discordCrypt.__cipherIndexToString( cipher_index )}-` +
                        `${this.discordCrypt.__cipherIndexToString( cipher_index, true )}`;

                    /* Create the test class. */
                    let test_name = `encode-${cipher_string}-${block_mode}-${padding_scheme}`;
                    unit_tests[ test_name ] = {};

                    /* Loop over each test being performed. */
                    for ( let l = 0; l < ( coverage ? 1 : vectors[ i ][ j ][ k ].r.length ); l++ ) {

                        /* Create a test. */
                        unit_tests[ test_name ][ `Test #${l}` ] = ( ut ) => {

                            /* Grab all data necessary. */
                            let primary_key = Buffer.from( vectors[ i ][ j ][ k ].r[ l ].primary_key, 'hex' ),
                                secondary_key = Buffer.from( vectors[ i ][ j ][ k ].r[ l ].secondary_key, 'hex' ),
                                plaintext = Buffer.from( vectors[ i ][ j ][ k ].r[ l ].plaintext, 'hex' ),
                                ciphertext = vectors[ i ][ j ][ k ].r[ l ].ciphertext;

                            /* Perform a decryption test. */
                            ut.equal(
                                plaintext.toString( 'utf8' ),
                                this.discordCrypt.__symmetricDecrypt(
                                    ciphertext,
                                    primary_key,
                                    secondary_key,
                                    cipher_index,
                                    this.ENCRYPT_BLOCK_MODES.indexOf( block_mode.toUpperCase() ),
                                    this.PADDING_SCHEMES.indexOf( padding_scheme.toUpperCase() ),
                                    true
                                ),
                                `Encoding error during decryption of ${cipher_string}`
                            );

                            /* Perform an encryption/decryption test. */
                            ut.equal(
                                plaintext.toString( 'utf8' ),
                                this.discordCrypt.__symmetricDecrypt(
                                    this.discordCrypt.__symmetricEncrypt(
                                        plaintext,
                                        primary_key,
                                        secondary_key,
                                        cipher_index,
                                        block_mode,
                                        padding_scheme,
                                        true
                                    ),
                                    primary_key,
                                    secondary_key,
                                    cipher_index,
                                    this.ENCRYPT_BLOCK_MODES.indexOf( block_mode.toUpperCase() ),
                                    this.PADDING_SCHEMES.indexOf( padding_scheme.toUpperCase() ),
                                    true
                                ),
                                `Encoding error during encryption of ${cipher_string}`
                            );

                            ut.done();
                        };
                    }
                }
            }
        }

    }

    /**
     * @desc Adds diffie hellman key exchange based tests to the array specified.
     * @param {Array} unit_tests An array of unit tests to run.
     * @param {boolean} coverage If enabled, only a single test is run. For coverage generation only.
     */
    addDiffieHellmanTests( unit_tests, coverage ) {
        const algorithms = [
            {
                name: 'DH',
                full_name: 'Diffie-Hellman',
                key_lengths: this.discordCrypt.__getDHBitSizes(),
            },
            {
                name: 'ECDH',
                full_name: 'Elliptic Curve Diffie-Hellman',
                key_lengths: this.discordCrypt.__getECDHBitSizes()
            }
        ];

        const tests = coverage === undefined ? 5 : 1;

        /* Loop over each algorithm. */
        for ( let i = 0; i < algorithms.length; i++ ) {
            /* Get the appropriate generator. */
            let generator = algorithms[ i ].name === 'DH' ?
                this.discordCrypt.__generateDH :
                this.discordCrypt.__generateECDH;

            /* Loop over each key size. */
            for ( let j = 0; j < algorithms[ i ].key_lengths.length; j++ ) {
                /* Generate a test class. */
                let test_name = `discordCrypt_${algorithms[ i ].name}_${algorithms[ i ].key_lengths[ j ]}`;
                unit_tests[ test_name ] = {};

                /* Loop over for the number of tests required. */
                for ( let k = 0; k < tests; k++ ) {
                    /* Create a test. */
                    unit_tests[ test_name ][ `Test #${k}` ] = ( ut ) => {
                        /* Generate both keys. */
                        let keyA = generator( algorithms[ i ].key_lengths[ j ] );
                        let keyB = generator( algorithms[ i ].key_lengths[ j ] );

                        /* Perform a key exchange and get the shared secret. */
                        let secretA =
                            this.discordCrypt
                                .__computeExchangeSharedSecret( keyA, keyB.getPublicKey( 'hex' ), false, true );

                        /* Get the secret for both keys. */
                        let secretB =
                            this.discordCrypt
                                .__computeExchangeSharedSecret( keyB, keyA.getPublicKey( 'hex' ), false, true );

                        /* Ensure the secrets match. */
                        ut.equal(
                            secretA,
                            secretB,
                            `${algorithms[ i ].full_name}-${algorithms[ i ].key_lengths[ j ]} failed`
                        );

                        /* Finish the test. */
                        ut.done();
                    };
                }
            }
        }
    }

    /**
     * @desc Adds general BetterDiscord based plugin tests.
     * @param {Array} unit_tests An array of unit tests to run.
     */
    addPluginBasedTests( unit_tests ) {
        /* Test the plugin's ability to log things and overwrite the logger with a non-HTML formatted one. */
        unit_tests.generic_tests[ 'Logging' ] = ( ut ) => {
            this.discordCrypt.log( 'Info', 'info' );
            this.discordCrypt.log( 'Error', 'error' );
            this.discordCrypt.log( 'Debug', 'debug' );
            this.discordCrypt.log( 'Warning', 'warn' );

            ut.done();
        };

        /* List general BetterDiscord info. */
        unit_tests.generic_tests[ 'Plugin Info' ] = ( ut ) => {
            this.discordCrypt.log(
                `Plugin: ${this.discordCrypt_instance.getName()} v${this.discordCrypt_instance.getVersion()}`
            );
            this.discordCrypt.log( `Author: ${this.discordCrypt_instance.getAuthor()}` );
            this.discordCrypt.log( `Description: ${this.discordCrypt_instance.getDescription()}` );

            // noinspection JSAccessibilityCheck
            this.discordCrypt.log(
                `Configuration:\n${JSON.stringify( this.discordCrypt._getDefaultConfig(), undefined, ' ' )}`
            );

            // noinspection JSAccessibilityCheck
            this.discordCrypt.log( `Path: ${this.discordCrypt._getPluginsPath()}` );

            ut.done();
        };

        /* Plugin update test.  */
        unit_tests.generic_tests[ 'Plugin Update' ] = ( ut ) => {
            // noinspection JSAccessibilityCheck
            this.discordCrypt._checkForUpdate( ( info ) => {
                /* Only called if the master branch's hash doesn't match this file's. */
                ut.equal( info.payload.length > 0, true, 'Failed to retrieve update file.' );
                ut.equal( info.hash.length > 0, true, 'Failed to retrieve update file hash.' );
                ut.equal( info.version.length > 0, true, 'Failed to retrieve the update version.' );
                ut.equal( info.changelog.length > 0, true, 'Failed to retrieve the changelog.' );
            } );

            /* Test will be completed regardless of if an update is found. */
            ut.done();
        };
    }

    /**
     * @desc Adds general file uploading test to the Riseup service.
     * @param {Array} unit_tests An array of unit tests to run.
     */
    addEncryptedFileTests( unit_tests ) {
        const vectors = require( './vectors/sjcl-test-vectors.json' );

        /* SJCL Library test. */
        unit_tests.generic_tests[ 'SJCL' ] = {};
        for( let i = 0; i < vectors.length; i++ ) {
            unit_tests.generic_tests[ 'SJCL' ][ `Test ${i}` ] = ( ut ) => {
                this.discordCrypt.__up1EncryptBuffer(
                    Buffer.from( vectors[ i ].buffer ),
                    '',
                    '',
                    global.sjcl,
                    ( err ) => {
                        ut.equal( err, null, `An error occurred: ${err}` );
                    },
                    Buffer.from( vectors[ i ].seed, 'base64' )
                );

                ut.done();
            };
        }

        /* File upload test. */
        unit_tests.generic_tests[ 'Encrypted File Upload' ] = ( ut ) => {
            this.discordCrypt.__up1UploadFile(
                './tests/test-generator.js',
                'https://share.riseup.net',
                '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
                global.sjcl,
                ( error, file_url, deletion_link, seed ) => {
                    /* Succeeds only if the error is null. */
                    ut.equal( error, null );

                    /* All these should be strings. */
                    ut.equal( typeof file_url, 'string' );
                    ut.equal( typeof deletion_link, 'string' );

                    ut.equal( typeof seed, 'string' );

                    console.log( `✔ -> ${file_url}` );
                    console.log( `✔ -> ${deletion_link}` );

                    ut.done();
                }
            );
        };

        /* Clipboard upload test. */
        unit_tests.generic_tests[ 'Encrypted Clipboard Upload' ] = ( ut ) => {
            this.discordCrypt.__up1UploadClipboard(
                'https://share.riseup.net',
                '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
                global.sjcl,
                ( error, file_url, deletion_link, seed ) => {
                    /* Succeeds only if the error is null. */
                    ut.equal( error, null );

                    /* All these should be strings. */
                    ut.equal( typeof file_url, 'string' );
                    ut.equal( typeof deletion_link, 'string' );

                    ut.equal( typeof seed, 'string' );

                    console.log( `✔ -> ${file_url}` );
                    console.log( `✔ -> ${deletion_link}` );

                    ut.done();
                },
                {
                    name: '',
                    mime_type: 'text/plain',
                    data: new Buffer( 'This is a pseudo-clipboard upload test!' )
                }
            );
        };
    }

    /**
     * @desc Adds metadata encoding and decoding tests.
     * @param {Array} unit_tests An array of unit tests to run.
     */
    addMetadataTests( unit_tests ) {
        const ids =
            [
                [
                    [ "⠀⠀⠀⠀", "⠀⠀⠁⠀", "⠀⠀⠂⠀", "⠀⠀⠃⠀" ],
                    [ "⠀⠁⠀⠀", "⠀⠁⠁⠀", "⠀⠁⠂⠀", "⠀⠁⠃⠀" ],
                    [ "⠀⠂⠀⠀", "⠀⠂⠁⠀", "⠀⠂⠂⠀", "⠀⠂⠃⠀" ]
                ],
                [
                    [ "⠁⠀⠀⠀", "⠁⠀⠁⠀", "⠁⠀⠂⠀", "⠁⠀⠃⠀" ],
                    [ "⠁⠁⠀⠀", "⠁⠁⠁⠀", "⠁⠁⠂⠀", "⠁⠁⠃⠀" ],
                    [ "⠁⠂⠀⠀", "⠁⠂⠁⠀", "⠁⠂⠂⠀", "⠁⠂⠃⠀" ]
                ],
                [
                    [ "⠂⠀⠀⠀", "⠂⠀⠁⠀", "⠂⠀⠂⠀", "⠂⠀⠃⠀" ],
                    [ "⠂⠁⠀⠀", "⠂⠁⠁⠀", "⠂⠁⠂⠀", "⠂⠁⠃⠀" ],
                    [ "⠂⠂⠀⠀", "⠂⠂⠁⠀", "⠂⠂⠂⠀", "⠂⠂⠃⠀" ]
                ],
                [
                    [ "⠃⠀⠀⠀", "⠃⠀⠁⠀", "⠃⠀⠂⠀", "⠃⠀⠃⠀" ],
                    [ "⠃⠁⠀⠀", "⠃⠁⠁⠀", "⠃⠁⠂⠀", "⠃⠁⠃⠀" ],
                    [ "⠃⠂⠀⠀", "⠃⠂⠁⠀", "⠃⠂⠂⠀", "⠃⠂⠃⠀" ]
                ],
                [
                    [ "⠄⠀⠀⠀", "⠄⠀⠁⠀", "⠄⠀⠂⠀", "⠄⠀⠃⠀" ],
                    [ "⠄⠁⠀⠀", "⠄⠁⠁⠀", "⠄⠁⠂⠀", "⠄⠁⠃⠀" ],
                    [ "⠄⠂⠀⠀", "⠄⠂⠁⠀", "⠄⠂⠂⠀", "⠄⠂⠃⠀" ]
                ],
                [
                    [ "⠅⠀⠀⠀", "⠅⠀⠁⠀", "⠅⠀⠂⠀", "⠅⠀⠃⠀" ],
                    [ "⠅⠁⠀⠀", "⠅⠁⠁⠀", "⠅⠁⠂⠀", "⠅⠁⠃⠀" ],
                    [ "⠅⠂⠀⠀", "⠅⠂⠁⠀", "⠅⠂⠂⠀", "⠅⠂⠃⠀" ]
                ],
                [
                    [ "⠆⠀⠀⠀", "⠆⠀⠁⠀", "⠆⠀⠂⠀", "⠆⠀⠃⠀" ],
                    [ "⠆⠁⠀⠀", "⠆⠁⠁⠀", "⠆⠁⠂⠀", "⠆⠁⠃⠀" ],
                    [ "⠆⠂⠀⠀", "⠆⠂⠁⠀", "⠆⠂⠂⠀", "⠆⠂⠃⠀" ]
                ],
                [
                    [ "⠇⠀⠀⠀", "⠇⠀⠁⠀", "⠇⠀⠂⠀", "⠇⠀⠃⠀" ],
                    [ "⠇⠁⠀⠀", "⠇⠁⠁⠀", "⠇⠁⠂⠀", "⠇⠁⠃⠀" ],
                    [ "⠇⠂⠀⠀", "⠇⠂⠁⠀", "⠇⠂⠂⠀", "⠇⠂⠃⠀" ]
                ],
                [
                    [ "⠈⠀⠀⠀", "⠈⠀⠁⠀", "⠈⠀⠂⠀", "⠈⠀⠃⠀" ],
                    [ "⠈⠁⠀⠀", "⠈⠁⠁⠀", "⠈⠁⠂⠀", "⠈⠁⠃⠀" ],
                    [ "⠈⠂⠀⠀", "⠈⠂⠁⠀", "⠈⠂⠂⠀", "⠈⠂⠃⠀" ]
                ],
                [
                    [ "⠉⠀⠀⠀", "⠉⠀⠁⠀", "⠉⠀⠂⠀", "⠉⠀⠃⠀" ],
                    [ "⠉⠁⠀⠀", "⠉⠁⠁⠀", "⠉⠁⠂⠀", "⠉⠁⠃⠀" ],
                    [ "⠉⠂⠀⠀", "⠉⠂⠁⠀", "⠉⠂⠂⠀", "⠉⠂⠃⠀" ]
                ],
                [
                    [ "⠊⠀⠀⠀", "⠊⠀⠁⠀", "⠊⠀⠂⠀", "⠊⠀⠃⠀" ],
                    [ "⠊⠁⠀⠀", "⠊⠁⠁⠀", "⠊⠁⠂⠀", "⠊⠁⠃⠀" ],
                    [ "⠊⠂⠀⠀", "⠊⠂⠁⠀", "⠊⠂⠂⠀", "⠊⠂⠃⠀" ]
                ],
                [
                    [ "⠋⠀⠀⠀", "⠋⠀⠁⠀", "⠋⠀⠂⠀", "⠋⠀⠃⠀" ],
                    [ "⠋⠁⠀⠀", "⠋⠁⠁⠀", "⠋⠁⠂⠀", "⠋⠁⠃⠀" ],
                    [ "⠋⠂⠀⠀", "⠋⠂⠁⠀", "⠋⠂⠂⠀", "⠋⠂⠃⠀" ]
                ],
                [
                    [ "⠌⠀⠀⠀", "⠌⠀⠁⠀", "⠌⠀⠂⠀", "⠌⠀⠃⠀" ],
                    [ "⠌⠁⠀⠀", "⠌⠁⠁⠀", "⠌⠁⠂⠀", "⠌⠁⠃⠀" ],
                    [ "⠌⠂⠀⠀", "⠌⠂⠁⠀", "⠌⠂⠂⠀", "⠌⠂⠃⠀" ]
                ],
                [
                    [ "⠍⠀⠀⠀", "⠍⠀⠁⠀", "⠍⠀⠂⠀", "⠍⠀⠃⠀" ],
                    [ "⠍⠁⠀⠀", "⠍⠁⠁⠀", "⠍⠁⠂⠀", "⠍⠁⠃⠀" ],
                    [ "⠍⠂⠀⠀", "⠍⠂⠁⠀", "⠍⠂⠂⠀", "⠍⠂⠃⠀" ]
                ],
                [
                    [ "⠎⠀⠀⠀", "⠎⠀⠁⠀", "⠎⠀⠂⠀", "⠎⠀⠃⠀" ],
                    [ "⠎⠁⠀⠀", "⠎⠁⠁⠀", "⠎⠁⠂⠀", "⠎⠁⠃⠀" ],
                    [ "⠎⠂⠀⠀", "⠎⠂⠁⠀", "⠎⠂⠂⠀", "⠎⠂⠃⠀" ]
                ],
                [
                    [ "⠏⠀⠀⠀", "⠏⠀⠁⠀", "⠏⠀⠂⠀", "⠏⠀⠃⠀" ],
                    [ "⠏⠁⠀⠀", "⠏⠁⠁⠀", "⠏⠁⠂⠀", "⠏⠁⠃⠀" ],
                    [ "⠏⠂⠀⠀", "⠏⠂⠁⠀", "⠏⠂⠂⠀", "⠏⠂⠃⠀" ]
                ],
                [
                    [ "⠐⠀⠀⠀", "⠐⠀⠁⠀", "⠐⠀⠂⠀", "⠐⠀⠃⠀" ],
                    [ "⠐⠁⠀⠀", "⠐⠁⠁⠀", "⠐⠁⠂⠀", "⠐⠁⠃⠀" ],
                    [ "⠐⠂⠀⠀", "⠐⠂⠁⠀", "⠐⠂⠂⠀", "⠐⠂⠃⠀" ]
                ],
                [
                    [ "⠑⠀⠀⠀", "⠑⠀⠁⠀", "⠑⠀⠂⠀", "⠑⠀⠃⠀" ],
                    [ "⠑⠁⠀⠀", "⠑⠁⠁⠀", "⠑⠁⠂⠀", "⠑⠁⠃⠀" ],
                    [ "⠑⠂⠀⠀", "⠑⠂⠁⠀", "⠑⠂⠂⠀", "⠑⠂⠃⠀" ]
                ],
                [
                    [ "⠒⠀⠀⠀", "⠒⠀⠁⠀", "⠒⠀⠂⠀", "⠒⠀⠃⠀" ],
                    [ "⠒⠁⠀⠀", "⠒⠁⠁⠀", "⠒⠁⠂⠀", "⠒⠁⠃⠀" ],
                    [ "⠒⠂⠀⠀", "⠒⠂⠁⠀", "⠒⠂⠂⠀", "⠒⠂⠃⠀" ]
                ],
                [
                    [ "⠓⠀⠀⠀", "⠓⠀⠁⠀", "⠓⠀⠂⠀", "⠓⠀⠃⠀" ],
                    [ "⠓⠁⠀⠀", "⠓⠁⠁⠀", "⠓⠁⠂⠀", "⠓⠁⠃⠀" ],
                    [ "⠓⠂⠀⠀", "⠓⠂⠁⠀", "⠓⠂⠂⠀", "⠓⠂⠃⠀" ]
                ],
                [
                    [ "⠔⠀⠀⠀", "⠔⠀⠁⠀", "⠔⠀⠂⠀", "⠔⠀⠃⠀" ],
                    [ "⠔⠁⠀⠀", "⠔⠁⠁⠀", "⠔⠁⠂⠀", "⠔⠁⠃⠀" ],
                    [ "⠔⠂⠀⠀", "⠔⠂⠁⠀", "⠔⠂⠂⠀", "⠔⠂⠃⠀" ]
                ],
                [
                    [ "⠕⠀⠀⠀", "⠕⠀⠁⠀", "⠕⠀⠂⠀", "⠕⠀⠃⠀" ],
                    [ "⠕⠁⠀⠀", "⠕⠁⠁⠀", "⠕⠁⠂⠀", "⠕⠁⠃⠀" ],
                    [ "⠕⠂⠀⠀", "⠕⠂⠁⠀", "⠕⠂⠂⠀", "⠕⠂⠃⠀" ]
                ],
                [
                    [ "⠖⠀⠀⠀", "⠖⠀⠁⠀", "⠖⠀⠂⠀", "⠖⠀⠃⠀" ],
                    [ "⠖⠁⠀⠀", "⠖⠁⠁⠀", "⠖⠁⠂⠀", "⠖⠁⠃⠀" ],
                    [ "⠖⠂⠀⠀", "⠖⠂⠁⠀", "⠖⠂⠂⠀", "⠖⠂⠃⠀" ]
                ],
                [
                    [ "⠗⠀⠀⠀", "⠗⠀⠁⠀", "⠗⠀⠂⠀", "⠗⠀⠃⠀" ],
                    [ "⠗⠁⠀⠀", "⠗⠁⠁⠀", "⠗⠁⠂⠀", "⠗⠁⠃⠀" ],
                    [ "⠗⠂⠀⠀", "⠗⠂⠁⠀", "⠗⠂⠂⠀", "⠗⠂⠃⠀" ]
                ],
                [
                    [ "⠘⠀⠀⠀", "⠘⠀⠁⠀", "⠘⠀⠂⠀", "⠘⠀⠃⠀" ],
                    [ "⠘⠁⠀⠀", "⠘⠁⠁⠀", "⠘⠁⠂⠀", "⠘⠁⠃⠀" ],
                    [ "⠘⠂⠀⠀", "⠘⠂⠁⠀", "⠘⠂⠂⠀", "⠘⠂⠃⠀" ]
                ]
            ];

        let test_name = 'discordCrypt_metadata';
        unit_tests[ test_name ] = {};

        /* Loop over each cipher index. */
        for ( let i = 0; i < ids.length; i++ ) {
            /* Loop over each block mode index. */
            for ( let j = 0; j < ids[ i ].length; j++ ) {
                /* Loop over each padding scheme index. */
                for ( let k = 0; k < ids[ i ][ j ].length; k++ ) {
                    /* Create the test ID. */
                    let id = `Test #${i}-${j}-${k}`;

                    /* Create the test. */
                    unit_tests[ test_name ][ id ] = ( ut ) => {

                        /* Check decoding works. */
                        ut.equal(
                            this.discordCrypt.__metaDataEncode( i, j, k, 0 ),
                            ids[ i ][ j ][ k ],
                            'Failed to encode metadata correctly.'
                        );

                        /* Encode the current index info. */
                        let decoded = this.discordCrypt.__metaDataDecode( ids[ i ][ j ][ k ] );

                        /* Validate all info is correct. */
                        ut.equal( i, decoded[ 0 ], 'Failed decoding cipher index.' );
                        ut.equal( j, decoded[ 1 ], 'Failed decoding block operation index.' );
                        ut.equal( k, decoded[ 2 ], 'Failed decoding padding scheme index.' );
                        ut.equal( 0, decoded[ 3 ], 'Failed to decode additional data.' );

                        ut.done();
                    };
                }
            }
        }
    }

    /**
     * @desc Adds generic plugin tests not classified by other types.
     * @param {Array} unit_tests An array of unit tests to run.
     */
    addGenericTests( unit_tests ) {
        unit_tests.generic_tests = {};

        /* Add general plugin info tests. */
        this.addPluginBasedTests( unit_tests );

        /* Add file upload tests. */
        this.addEncryptedFileTests( unit_tests );

        /* Add metadata encoding tests. */
        this.addMetadataTests( unit_tests );
    }
}

( new testRunner() );
