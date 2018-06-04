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

/* Required for unit tests. */
const nodeunit = require('nodeunit');

class testRunner {
    constructor() {
        this.fs = require( 'fs' );
        this.process = require( 'process' );

        this.discordCrypt = require( '../src/discordCrypt.plugin.js' ).discordCrypt;

        this.discordCrypt_instance = new ( this.discordCrypt )();
    }

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

            /* Run key exchange tests. */
            this.addDiffieHellmanTests( unit_tests );
        }

        /* Actually run all the tests. */
        nodeunit.reporters.default.run( unit_tests );
    }

    /* Runs Scrypt tests. */
    addScryptTests( unit_tests, coverage ) {
        const vectors = require( './scrypt-test-vectors' );

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_scrypt = {};

        /* Loop over all tests. */
        let num_tests = coverage === undefined ? vectors.length : 1;
        for ( let i = 0; i < num_tests; i++ ) {
            let v = vectors[ i ],
                k = `Test #${Object.keys( unit_tests.discordCrypt_scrypt ).length + 1}: [ N: ${v.N} r: ${v.r} p: ${v.p} ]`;

            /* Create a function callback for this test name. */
            unit_tests.discordCrypt_scrypt[ k ] = ( ut ) => {
                /* Convert the password and salt to Buffer objects. */
                let password = new Buffer( v.password, 'hex' );
                let salt = new Buffer( v.salt, 'hex' );

                /* Save the key. */
                let derivedKey = v.derivedKey;

                /* Passed from the loaded class file. */
                this.discordCrypt.scrypt( password, salt, v.dkLen, v.N, v.r, v.p, ( error, progress, key ) => {
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

    /* Run PBKDF2 tests. */
    addPBKDF2Tests( unit_tests, coverage ) {

        /* Load the test units. */
        const hash_vectors = require( './pbkdf2-test-vectors.json' );
        const hash_list = [
            {
                name: 'sha1',
                length: 20
            },
            {
                name: 'sha256',
                length: 32
            },
            {
                name: 'sha512',
                length: 64
            },
            {
                name: 'whirlpool',
                length: 64
            }
        ];

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_pbkdf2 = {};

        /* Run a unit for a target. */
        function prepare_run( instance, name, hash_size, /* Object */ v ) {
            for ( let i = 0; i < ( coverage === undefined ? v.length : 1 ); i++ ) {
                let format =
                    `${name}: Test #${Object.keys( unit_tests.discordCrypt_pbkdf2 ).length}`;

                unit_tests.discordCrypt_pbkdf2[ format ] = ( ut ) => {
                    let hash = instance.discordCrypt.__pbkdf2(
                        new Buffer( v[ i ].password, 'utf8' ),
                        new Buffer( v[ i ].salt, 'utf8' ),
                        true,
                        undefined,
                        undefined,
                        undefined,
                        name,
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
            prepare_run( this, hash_list[ i ].name, hash_list[ i ].length, hash_vectors );
    }

    /* Run hash tests. */
    addHashTests( unit_tests, coverage ) {

        /* Load the test units. */
        const hash_vectors = require( './hash-test-vectors.json' );
        const hash_list = [
            {
                name: 'sha1',
                length: 20,
                hash: this.discordCrypt.sha160,
            },
            {
                name: 'sha256',
                length: 32,
                hash: this.discordCrypt.sha256,
            },
            {
                name: 'sha512',
                length: 64,
                hash: this.discordCrypt.sha512,
            },
            {
                name: 'sha512_128',
                length: 16,
                hash: this.discordCrypt.sha512_128,
            },
            {
                name: 'whirlpool',
                length: 64,
                hash: this.discordCrypt.whirlpool,
            },
            {
                name: 'whirlpool64',
                length: 8,
                hash: this.discordCrypt.whirlpool64,
            },
            {
                name: 'whirlpool192',
                length: 24,
                hash: this.discordCrypt.whirlpool192,
            }
        ];

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_hash = {};

        /* Finds the hash algorithm. */
        function find_hash_algorithm( /* string */ name ) {
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

    /* Run hash tests. */
    addHMACTests( unit_tests, coverage ) {

        /* Load the test units. */
        const hash_vectors = require( './hmac-test-vectors.json' );
        const hmac_list = [
            {
                name: 'hmac_sha256',
                length: 32,
                hash: this.discordCrypt.hmac_sha256,
            },
            {
                name: 'hmac_sha512',
                length: 64,
                hash: this.discordCrypt.hmac_sha512,
            },
            {
                name: 'hmac_whirlpool',
                length: 64,
                hash: this.discordCrypt.hmac_whirlpool,
            }
        ];

        /* Prepare the unit tests. */
        unit_tests.discordCrypt_hmac = {};

        /* Finds the hash algorithm. */
        function find_hash_algorithm( /* string */ name ) {
            for ( let i = 0; i < hmac_list.length; i++ )
                if ( name == hmac_list[ i ].name )
                    return hmac_list[ i ].hash;
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

    /* Run Cipher tests. */
    addCipherTests( unit_tests, preferred_cipher = undefined, coverage ) {
        const vectors = require( './cipher-test-vectors.json' );

        /* Locates the given array containing the target's test vectors. */
        function locateTestVector( /* Array */ list, /* string */ name ) {
            for ( let i = 0; i < list.length; i++ ) {
                if ( list[ i ].full_name.toLowerCase() === name.toLowerCase() )
                    return list[ i ];
            }

            return null;
        }

        /* Adds a cipher test list to be checked. */
        function addCipherTest(
            /* Object */     unit_tests,
            /* string */     cipher_name,
            /* Array */      test_vectors,
            /* function() */ encrypt,
            /* function() */ decrypt
        ) {
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
                                /* As a result, we only test ciphertext equality in padding schemes that don't do this. */
                                if ( scheme.toLowerCase() !== 'iso1' ) {
                                    if ( mode !== 'gcm' )
                                    /* Perform an encryption routine with the predefined key and KDF salt. */
                                        _ciphertext = encrypt( plaintext, key, mode, scheme, true, false, salt );
                                    else
                                    /* Perform an encryption routine with the predefined key and KDF salt. */
                                        _ciphertext = encrypt( plaintext, key, scheme, true, false, undefined, salt );

                                    /* Check if the plaintext and ciphertext calculate match the expected output. */
                                    ut.equal( _ciphertext, test_vectors[ i ][ j ].r[ k ].ciphertext, 'Mismatched ciphertext' );
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
                                    ut.equal( _plaintext, test_vectors[ i ][ j ].r[ k ].plaintext, 'Encryption failure' );
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
                    this.discordCrypt.aes256_encrypt,
                    this.discordCrypt.aes256_decrypt
                );
                addCipherTest(
                    unit_tests,
                    aes_gcm_vectors.full_name,
                    aes_gcm_vectors.tests,
                    this.discordCrypt.aes256_encrypt_gcm,
                    this.discordCrypt.aes256_decrypt_gcm
                );
                break;
            case 'camellia':
            case 'camellia256':
            case 'camellia-256':
                addCipherTest(
                    unit_tests,
                    camellia_vectors.full_name,
                    camellia_vectors.tests,
                    this.discordCrypt.camellia256_encrypt,
                    this.discordCrypt.camellia256_decrypt
                );
                break;
            case 'tripledes':
            case 'tripledes192':
            case 'tripledes-192':
                addCipherTest(
                    unit_tests,
                    tripledes_vectors.full_name,
                    tripledes_vectors.tests,
                    this.discordCrypt.tripledes192_encrypt,
                    this.discordCrypt.tripledes192_decrypt
                );
                break;
            case 'idea':
            case 'idea128':
            case 'idea-128':
                addCipherTest(
                    unit_tests,
                    idea_vectors.full_name,
                    idea_vectors.tests,
                    this.discordCrypt.idea128_encrypt,
                    this.discordCrypt.idea128_decrypt
                );
                break;
            case 'blowfish':
            case 'blowfish512':
            case 'blowfish-512':
                addCipherTest(
                    unit_tests,
                    blowfish_vectors.full_name,
                    blowfish_vectors.tests,
                    this.discordCrypt.blowfish512_encrypt,
                    this.discordCrypt.blowfish512_decrypt
                );
                break;
            default:
                addCipherTest(
                    unit_tests,
                    aes_vectors.full_name,
                    aes_vectors.tests,
                    this.discordCrypt.aes256_encrypt,
                    this.discordCrypt.aes256_decrypt
                );
                addCipherTest(
                    unit_tests,
                    aes_gcm_vectors.full_name,
                    aes_gcm_vectors.tests,
                    this.discordCrypt.aes256_encrypt_gcm,
                    this.discordCrypt.aes256_decrypt_gcm
                );
                addCipherTest(
                    unit_tests,
                    camellia_vectors.full_name,
                    camellia_vectors.tests,
                    this.discordCrypt.camellia256_encrypt,
                    this.discordCrypt.camellia256_decrypt
                );
                addCipherTest(
                    unit_tests,
                    tripledes_vectors.full_name,
                    tripledes_vectors.tests,
                    this.discordCrypt.tripledes192_encrypt,
                    this.discordCrypt.tripledes192_decrypt
                );
                addCipherTest(
                    unit_tests,
                    idea_vectors.full_name,
                    idea_vectors.tests,
                    this.discordCrypt.idea128_encrypt,
                    this.discordCrypt.idea128_decrypt
                );
                addCipherTest(
                    unit_tests,
                    blowfish_vectors.full_name,
                    blowfish_vectors.tests,
                    this.discordCrypt.blowfish512_encrypt,
                    this.discordCrypt.blowfish512_decrypt
                );
                break;
        }
    }

    /* Run Diffie-Hellman exchange tests. */
    addDiffieHellmanTests( unit_tests, coverage ) {
        const algorithms = [
            {
                name: 'DH',
                full_name: 'Diffie-Hellman',
                key_lengths: this.discordCrypt.getDHBitSizes(),
            },
            {
                name: 'ECDH',
                full_name: 'Elliptic Curve Diffie-Hellman',
                key_lengths: this.discordCrypt.getECDHBitSizes()
            }
        ];

        const tests = coverage === undefined ? 5 : 1;

        /* Loop over each algorithm. */
        for ( let i = 0; i < algorithms.length; i++ ) {
            /* Get the appropriate generator. */
            let generator = algorithms[ i ].name === 'DH' ?
                this.discordCrypt.generateDH :
                this.discordCrypt.generateECDH;

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
                                .computeExchangeSharedSecret( keyA, keyB.getPublicKey( 'hex' ), false, true );

                        /* Get the secret for both keys. */
                        let secretB =
                            this.discordCrypt
                                .computeExchangeSharedSecret( keyB, keyA.getPublicKey( 'hex' ), false, true );

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

    /* Adds generic plugin tests not classified by other types. */
    addGenericTests( unit_tests ) {
        let DiscordCrypt = this.discordCrypt_instance;
        let discordCrypt = this.discordCrypt;

        unit_tests.generic_tests = {};

        /* Test the plugin's ability to log things and overwrite the logger with a non-HTML formatted one. */
        unit_tests.generic_tests[ 'Logging' ] = ( ut ) => {
            discordCrypt.log( 'Info', 'info' );
            discordCrypt.log( 'Error', 'error' );
            discordCrypt.log( 'Debug', 'debug' );
            discordCrypt.log( 'Warning', 'warn' );

            discordCrypt.log = ( /* string */ message, /* string */ method = "info" ) => {
                try {
                    console[ method ]( "[DiscordCrypt] - " + message );
                }
                catch ( ex ) {
                }
            };

            ut.done();
        };

        /* List general BetterDiscord info. */
        unit_tests.generic_tests[ 'Plugin Info' ] = ( ut ) => {
            discordCrypt.log( `Plugin: ${DiscordCrypt.getName()} v${DiscordCrypt.getVersion()}` );
            discordCrypt.log( `Author: ${DiscordCrypt.getAuthor()}` );
            discordCrypt.log( `Description: ${DiscordCrypt.getDescription()}` );

            discordCrypt.log( `Configuration:\n${JSON.stringify( DiscordCrypt.getDefaultConfig(), undefined, ' ' )}` );

            discordCrypt.log( `Path: ${discordCrypt.getPluginsPath()}` );

            ut.done();
        };

        /* Plugin update test.  */
        unit_tests.generic_tests[ 'Plugin Update' ] = ( ut ) => {
            discordCrypt.checkForUpdate( ( file_data, short_hash, new_version, full_changelog ) => {
                /* Only called if the master branch's hash doesn't match this file's. */
                ut.equal( file_data.length > 0, true, 'Failed to retrieve update file.' );
                ut.equal( short_hash.length > 0, true, 'Failed to retrieve update file hash.' );
                ut.equal( new_version.length > 0, true, 'Failed to retrieve the update version.' );
                ut.equal( full_changelog.length > 0, true, 'Failed to retrieve the changelog.' );
            } );

            /* Test will be completed regardless of if an update is found. */
            ut.done();
        };

        /* File upload test. */
        unit_tests.generic_tests[ 'Encrypted File Upload' ] = ( ut ) => {
            discordCrypt.__up1UploadFile(
                './tests/test_generator.js',
                'https://share.riseup.net',
                '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
                require( './sjcl' ),
                ( error, file_url, deletion_link, seed ) => {
                    /* Succeeds only if the error is null. */
                    ut.equal( error, null );

                    /* All these should be strings. */
                    ut.equal( typeof file_url, 'string' );
                    ut.equal( typeof deletion_link, 'string' );

                    ut.equal( typeof seed, 'string' );
                }
            );

            ut.done();
        };
    }
}

(new testRunner()).run();
