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

/* Locates the given array containing the target's test vectors. */
function locateTestVector(/* Array */ list, /* string */ name){
    for(let i = 0; i < list.length; i++){
        if(list[i].full_name.toLowerCase() === name.toLowerCase())
            return list[i];
    }

    return null;
}

/* Runs Scrypt tests. */
function addScryptTests(loaded_blob, unit_tests){
    const vectors = require('./scrypt-test-vectors');

    /* Prepare the unit tests. */
    unit_tests.discordCrypt_scrypt = {};

    /* Loop over all tests. */
    for (let i = 0; i < vectors.length; i++){
        let v = vectors[i],
            k = `Test #${Object.keys(unit_tests.discordCrypt_scrypt).length+1}: [ N: ${v.N} p: ${v.p} r: ${v.r} ]`;

        /* Create a function callback for this test name. */
        unit_tests.discordCrypt_scrypt[k] = (ut) => {
            /* Convert the password and salt to Buffer objects. */
            let password = new Buffer(v.password, 'hex');
            let salt = new Buffer(v.salt, 'hex');

            /* Save the key. */
            let derivedKey = v.derivedKey;

            /* Passed from the loaded class file. */
            loaded_blob['class'].scrypt(password, salt, v.dkLen, v.N, v.r, v.p, (error, progress, key) => {
                /* On errors, let the user know. */
                if (error){
                    loaded_blob['class'].log(error);
                    return;
                }

                /* Once the key has been calculated, check it. */
                if (key) {
                    ut.equal(derivedKey, key.toString('hex'), 'Derived key check failed.');
                    ut.done();
                }
            });
        };
    }
}

/* Run PBKDF2 tests. */
function addPBKDF2Tests(loaded_blob, unit_tests){
    /**
     * Expected:
     *
     * discordCrypt_pbkdf2
     * ✔ sha1: Test #1
     * ✔ sha1: Test #2
     * ✔ sha1: Test #3
     * ✔ sha1: Test #4
     * ✔ sha1: Test #5
     * ✔ sha1: Test #6
     * ✔ sha1: Test #7
     * ✔ sha1: Test #8
     * ✔ sha256: Test #9
     * ✔ sha256: Test #10
     * ✔ sha256: Test #11
     * ✔ sha256: Test #12
     * ✔ sha256: Test #13
     * ✔ sha256: Test #14
     * ✔ sha256: Test #15
     * ✔ sha256: Test #16
     * ✔ sha512: Test #17
     * ✔ sha512: Test #18
     * ✔ sha512: Test #19
     * ✔ sha512: Test #20
     * ✔ sha512: Test #21
     * ✔ sha512: Test #22
     * ✔ sha512: Test #23
     * ✔ sha512: Test #24
     * ✔ whirlpool: Test #25
     * ✔ whirlpool: Test #26
     * ✔ whirlpool: Test #27
     * ✔ whirlpool: Test #28
     * ✔ whirlpool: Test #29
     * ✔ whirlpool: Test #30
     * ✔ whirlpool: Test #31
     * ✔ whirlpool: Test #32
     */

    /* Load the test units. */
    const hash_vectors = require('./hash-test-vectors.json');
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
    unit_tests.discordCrypt_pbkdf2 =  {};

    /* Run a unit for a target. */
    function prepare_run(name, hash_size, /* Array */ loaded_blob, /* Object */ v){
        let pbkdf2 = loaded_blob['class'].__pbkdf2;

        for(let i = 0; i < v.length; i++){
            let format =
                `${name}: Test #${Object.keys(unit_tests.discordCrypt_pbkdf2).length}`;

            unit_tests.discordCrypt_pbkdf2[format] = (ut) => {
                let hash = pbkdf2(
                    new Buffer(v[i].password, 'utf8'),
                    new Buffer(v[i].salt, 'utf8'),
                    true,
                    undefined,
                    undefined,
                    undefined,
                    name,
                    hash_size,
                    v[i].iterations
                );

                ut.equal(hash, v[i][name], `Hash mismatch for ${name}.`);
                ut.done();
            };
        }
    }

    /* Register all tests. */
    for(let i = 0; i < hash_list.length; i++)
        prepare_run(hash_list[i].name, hash_list[i].length, loaded_blob, hash_vectors);
}

/* Run Cipher tests. */
function addCipherTests(loaded_blob, unit_tests, preferred_cipher = undefined){
    const vectors = require('./cipher-test-vectors.json');

    /* Adds a cipher test list to be checked. */
    function addCipherTest(
        /* Object */     loaded_blob,
        /* Object */     unit_tests,
        /* string */     cipher_name,
        /* Array */      test_vectors,
        /* function() */ encrypt,
        /* function() */ decrypt
    ){
        /* Loop over each individual test. */
        for(let i = 0; i < test_vectors.length; i++){
            /* Loop over the block mode and padding scheme array. */
            for(let j = 0; j < test_vectors[i].length; j++){

                /* Backup. */
                let mode = test_vectors[i][j].mode;
                let scheme = test_vectors[i][j].scheme;

                /* Save this so future changes are easier. */
                let test_name = `discordCrypt-${cipher_name}-${mode.toUpperCase()}-${scheme.toUpperCase()}`;

                /* Create the test unit. */
                unit_tests[test_name] = {};

                /* Loop over each individual unit test. */
                for(let k = 0; k < test_vectors[i][j].r.length; k++){
                    /* Convert the target strings from hex format to Buffer objects. */
                    let plaintext = new Buffer(test_vectors[i][j].r[k].plaintext, 'hex');
                    let ciphertext = new Buffer(test_vectors[i][j].r[k].ciphertext, 'hex');

                    /* Extract the hex key and salts used. */
                    let key = new Buffer(test_vectors[i][j].r[k].key, 'hex');
                    let salt = new Buffer(test_vectors[i][j].r[k].salt, 'hex');

                    /* Backup test ID. */
                    let test_id = `Test #${k+1}`;

                    /* Create the test callback */
                    unit_tests[test_name][test_id] =
                        (ut) => {
                            let _plaintext, _ciphertext;

                            if(mode !== 'gcm')
                                /* Calculate the plaintext by doing a decryption cycle. */
                                _plaintext = decrypt(ciphertext, key, mode, scheme, 'hex');
                            else
                                _plaintext = decrypt(ciphertext, key, scheme, 'hex');

                            /* Check if they match. */
                            ut.equal(_plaintext, test_vectors[i][j].r[k].plaintext, 'Mismatched plaintext');

                            /* ISO-10126 uses random padding bytes which we can't predict. */
                            /* As a result, we only test ciphertext equality in padding schemes that don't do this. */
                            if(scheme.toLowerCase() !== 'iso1'){
                                if(mode !== 'gcm')
                                    /* Perform an encryption routine with the predefined key and KDF salt. */
                                    _ciphertext = encrypt(plaintext, key, mode, scheme, true, false, salt);
                                else
                                    /* Perform an encryption routine with the predefined key and KDF salt. */
                                    _ciphertext = encrypt(plaintext, key, scheme, true, false, undefined, salt);

                                /* Check if the plaintext and ciphertext calculate match the expected output. */
                                ut.equal(_ciphertext, test_vectors[i][j].r[k].ciphertext, 'Mismatched ciphertext');
                            }
                            else{
                                if(mode !== 'gcm'){
                                    /* Here, we simply test if the encryption validates. */
                                    _ciphertext = new Buffer(
                                        encrypt(plaintext, key, mode, scheme, true, false, salt),
                                        'hex'
                                    );

                                    /* Then we decrypt the ciphertext. */
                                    _plaintext = decrypt(_ciphertext, key, mode, scheme, 'hex');
                                }
                                else{
                                    /* Here, we simply test if the encryption validates. */
                                    _ciphertext = new Buffer(
                                        encrypt(plaintext, key, scheme, true, false, undefined, salt),
                                        'hex'
                                    );

                                    /* Then we decrypt the ciphertext. */
                                    _plaintext = decrypt(_ciphertext, key, scheme, 'hex');
                                }

                                /* Check if the newly decrypted plaintext is valid. */
                                ut.equal(_plaintext, test_vectors[i][j].r[k].plaintext, 'Encryption failure');
                            }

                            /* Finish the test. */
                            ut.done();
                        };
                }
            }
        }

    }

    /* Quick sanity check. */
    if(typeof preferred_cipher !== 'string')
        preferred_cipher = 'Running all cipher tests';

    /* Fetch all test vectors. */
    let aes_vectors = locateTestVector(vectors, 'aes-256'),
        aes_gcm_vectors = locateTestVector(vectors, 'aes-256-gcm'),
        camellia_vectors = locateTestVector(vectors, 'camellia-256'),
        tripledes_vectors = locateTestVector(vectors, 'tripledes-192'),
        idea_vectors = locateTestVector(vectors, 'idea-128'),
        blowfish_vectors = locateTestVector(vectors, 'blowfish-512');

    /* Locate the desired cipher. Tons of redundant code here :) */
    switch(preferred_cipher){
        case 'aes':
        case 'aes256':
        case 'aes-256':
            addCipherTest(
                loaded_blob,
                unit_tests,
                aes_vectors.full_name,
                aes_vectors.tests,
                loaded_blob['class'].aes256_encrypt,
                loaded_blob['class'].aes256_decrypt
            );
            addCipherTest(
                loaded_blob,
                unit_tests,
                aes_gcm_vectors.full_name,
                aes_gcm_vectors.tests,
                loaded_blob['class'].aes256_encrypt_gcm,
                loaded_blob['class'].aes256_decrypt_gcm
            );
            break;
        case 'camellia':
        case 'camellia256':
        case 'camellia-256':
            addCipherTest(
                loaded_blob,
                unit_tests,
                camellia_vectors.full_name,
                camellia_vectors.tests,
                loaded_blob['class'].camellia256_encrypt,
                loaded_blob['class'].camellia256_decrypt
            );
            break;
        case 'tripledes':
        case 'tripledes192':
        case 'tripledes-192':
            addCipherTest(
                loaded_blob,
                unit_tests,
                tripledes_vectors.full_name,
                tripledes_vectors.tests,
                loaded_blob['class'].tripledes192_encrypt,
                loaded_blob['class'].tripledes192_decrypt
            );
            break;
        case 'idea':
        case 'idea128':
        case 'idea-128':
            addCipherTest(
                loaded_blob,
                unit_tests,
                idea_vectors.full_name,
                idea_vectors.tests,
                loaded_blob['class'].idea128_encrypt,
                loaded_blob['class'].idea128_decrypt
            );
            break;
        case 'blowfish':
        case 'blowfish512':
        case 'blowfish-512':
            addCipherTest(
                loaded_blob,
                unit_tests,
                blowfish_vectors.full_name,
                blowfish_vectors.tests,
                loaded_blob['class'].blowfish512_encrypt,
                loaded_blob['class'].blowfish512_decrypt
            );
            break;
        default:
            addCipherTest(
                loaded_blob,
                unit_tests,
                aes_vectors.full_name,
                aes_vectors.tests,
                loaded_blob['class'].aes256_encrypt,
                loaded_blob['class'].aes256_decrypt
            );
            addCipherTest(
                loaded_blob,
                unit_tests,
                aes_gcm_vectors.full_name,
                aes_gcm_vectors.tests,
                loaded_blob['class'].aes256_encrypt_gcm,
                loaded_blob['class'].aes256_decrypt_gcm
            );
            addCipherTest(
                loaded_blob,
                unit_tests,
                camellia_vectors.full_name,
                camellia_vectors.tests,
                loaded_blob['class'].camellia256_encrypt,
                loaded_blob['class'].camellia256_decrypt
            );
            addCipherTest(
                loaded_blob,
                unit_tests,
                tripledes_vectors.full_name,
                tripledes_vectors.tests,
                loaded_blob['class'].tripledes192_encrypt,
                loaded_blob['class'].tripledes192_decrypt
            );
            addCipherTest(
                loaded_blob,
                unit_tests,
                idea_vectors.full_name,
                idea_vectors.tests,
                loaded_blob['class'].idea128_encrypt,
                loaded_blob['class'].idea128_decrypt
            );
            addCipherTest(
                loaded_blob,
                unit_tests,
                blowfish_vectors.full_name,
                blowfish_vectors.tests,
                loaded_blob['class'].blowfish512_encrypt,
                loaded_blob['class'].blowfish512_decrypt
            );
            break;
    }
}

/* Run Diffie-Hellman exchange tests. */
function addDiffieHellmanTests(loaded_blob, unit_tests){
    const algorithms = [
        {
            name: 'DH',
            full_name: 'Diffie-Hellman',
            key_lengths: loaded_blob['class'].getDHBitSizes(),
        },
        {
            name: 'ECDH',
            full_name: 'Elliptic Curve Diffie-Hellman',
            key_lengths: loaded_blob['class'].getECDHBitSizes()
        }
    ];

    const tests = 5;

    /* Loop over each algorithm. */
    for(let i = 0; i < algorithms.length; i++){
        /* Get the appropriate generator. */
        let generator = algorithms[i].name === 'DH' ?
            loaded_blob['class'].generateDH :
            loaded_blob['class'].generateECDH;

        /* Loop over each key size. */
        for(let j = 0; j < algorithms[i].key_lengths.length; j++){
            /* Generate a test class. */
            let test_name = `discordCrypt_${algorithms[i].name}_${algorithms[i].key_lengths[j]}`;
            unit_tests[test_name] = {};

            /* Loop over for the number of tests required. */
            for(let k = 0; k < tests; k++){
                /* Create a test. */
                unit_tests[test_name][`Test #${k}`] = (ut) => {
                    /* Generate both keys. */
                    let keyA = generator(algorithms[i].key_lengths[j]);
                    let keyB = generator(algorithms[i].key_lengths[j]);

                    /* Perform a key exchange and get the shared secret. */
                    let secretA =
                        loaded_blob['class'].computeExchangeSharedSecret(keyA, keyB.getPublicKey('hex'), false, true);

                    /* Get the secret for both keys. */
                    let secretB =
                        loaded_blob['class'].computeExchangeSharedSecret(keyB, keyA.getPublicKey('hex'), false, true);

                    /* Ensure the secrets match. */
                    ut.equal(secretA, secretB, `${algorithms[i].full_name}-${algorithms[i].key_lengths[j]} failed`);

                    /* Finish the test. */
                    ut.done();
                };
            }
        }
    }
}

/* Adds generic plugin tests not classified by other types. */
function addGenericTests(loaded_blob, unit_tests){
    let DiscordCrypt = loaded_blob['instance'];
    let discordCrypt = loaded_blob['class'];

    unit_tests.generic_tests = {};

    /* Test the plugin's ability to log things and overwrite the logger with a non-HTML formatted one. */
    unit_tests.generic_tests['Logging'] = (ut) => {
        discordCrypt.log('Info', 'info');
        discordCrypt.log('Error', 'error');
        discordCrypt.log('Debug', 'debug');
        discordCrypt.log('Warning', 'warn');

        discordCrypt.log = (/* string */ message, /* string */ method = "info") => {
            try{ console[method]("[DiscordCrypt] - " + message); }
            catch(ex) {}
        };

        ut.done();
    };

    /* List general BetterDiscord info. */
    unit_tests.generic_tests['Plugin Info'] = (ut) => {
        discordCrypt.log(`Plugin: ${DiscordCrypt.getName()} v${DiscordCrypt.getVersion()}`);
        discordCrypt.log(`Author: ${DiscordCrypt.getAuthor()}`);
        discordCrypt.log(`Description: ${DiscordCrypt.getDescription()}`);

        discordCrypt.log(`Configuration:\n${JSON.stringify(DiscordCrypt.getDefaultConfig(), undefined, ' ')}`);

        discordCrypt.log(`Path: ${discordCrypt.getPluginsPath()}`);

        ut.done();
    };

    /* Plugin update test.  */
    unit_tests.generic_tests['Plugin Update'] = (ut) => {
        discordCrypt.checkForUpdate((file_data, short_hash, new_version, full_changelog) => {
            /* Only called if the master branch's hash doesn't match this file's. */
            ut.equal(file_data.length > 0, true, 'Failed to retrieve update file.');
            ut.equal(short_hash.length > 0, true, 'Failed to retrieve update file hash.');
            ut.equal(new_version.length > 0, true, 'Failed to retrieve the update version.');
            ut.equal(full_changelog.length > 0, true, 'Failed to retrieve the changelog.');
        });

        /* Test will be completed regardless of if an update is found. */
        ut.done();
    };

    /* File upload test. */
    unit_tests.generic_tests['Encrypted File Upload'] = (ut) => {
        discordCrypt.__up1UploadFile(
            './tests/test_generator.js',
            'https://share.riseup.net',
            '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
            require('./sjcl'),
            (error, file_url, deletion_link, seed) => {
                /* Succeeds only if the error is null. */
                ut.equal(error, null);

                /* All these should be strings. */
                ut.equal(typeof file_url, 'string');
                ut.equal(typeof deletion_link, 'string');

                ut.equal(typeof seed, 'string');
            }
        );

        ut.done();
    };
}

/* Load the plugin from module exports. */
function loadDiscordCrypt(){
    let load = require('../src/discordCrypt.plugin.js');

    return {'class': load, 'instance': new load()};
}

/* Main function. */
function main(){
    const process = require('process');

    /* Actually load the plugin. */
    let loaded_blob = loadDiscordCrypt();

    /* Prepare the unit tests. */
    let unit_tests = {};

    /* Handle which tests to run. */
    try{
        switch(process.argv[2].toLowerCase()){
            case 'scrypt':
                /* Run Scrypt tests. */
                addScryptTests(loaded_blob, unit_tests);
                break;
            case 'pbkdf2':
                /* Run Hash/PBKDF2 tests. */
                addPBKDF2Tests(loaded_blob, unit_tests);
                break;
            case 'cipher':
                /* Run cipher tests. */
                addCipherTests(loaded_blob, unit_tests, process.argv.length >= 4 ? process.argv[3] : '');
                break;
            case 'general':
                /* Run generic tests. */
                addGenericTests(loaded_blob, unit_tests);
                break;
            case 'exchange':
                /* Run key exchange tests. */
                addDiffieHellmanTests(loaded_blob, unit_tests);
                break;
            default:
                throw 'Executing all tests.';
        }
    }
    catch(e){
        /* Run generic tests. */
        addGenericTests(loaded_blob, unit_tests);

        /* Run Scrypt tests. */
        addScryptTests(loaded_blob, unit_tests);

        /* Run Hash/PBKDF2 tests. */
        addPBKDF2Tests(loaded_blob, unit_tests);

        /* Run cipher tests. */
        addCipherTests(loaded_blob, unit_tests);

        /* Run key exchange tests. */
        addDiffieHellmanTests(loaded_blob, unit_tests);
    }

    /* Actually run all the tests. */
    nodeunit.reporters.default.run(unit_tests);
}

main();
