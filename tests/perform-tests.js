/* Required for unit tests. */
const nodeunit = require('nodeunit');

/* Runs Scrypt tests. */
function addScryptTests(loaded_blob, unit_tests){
    /* Reference: https://tools.ietf.org/html/rfc7914#page-13 */
    const vectors = require('./scrypt-test-vectors');

    /**
     * Expected Results:
     *
     * discordCrypt_scrypt
     * ✔ Test #1: [ N: 16 p: 1 r: 1 ]
     * ✔ Test #2: [ N: 1024 p: 16 r: 8 ]
     * ✔ Test #3: [ N: 16384 p: 1 r: 8 ]
     * ✔ Test #4: [ N: 1048576 p: 1 r: 8 ]
     * ✔ Test #5: [ N: 262144 p: 1 r: 8 ]
     */

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
                    console.log(error);
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
                            /* Calculate the plaintext by doing a decryption cycle. */
                            let _plaintext = decrypt(ciphertext, key, mode, scheme, 'hex');

                            /* Check if they match. */
                            ut.equal(_plaintext, test_vectors[i][j].r[k].plaintext, 'Mismatched plaintext');

                            /* ISO-10126 uses random padding bytes which we can't predict. */
                            /* As a result, we only test ciphertext equality in padding schemes that don't do this. */
                            if(scheme.toLowerCase() !== 'iso1'){
                                /* Perform an encryption routine with the predefined key and KDF salt. */
                                let _ciphertext = encrypt(plaintext, key, mode, scheme, true, false, salt);

                                /* Check if the plaintext and ciphertext calculate match the expected output. */
                                ut.equal(_ciphertext, test_vectors[i][j].r[k].ciphertext, 'Mismatched ciphertext');
                            }
                            else{
                                /* Here, we simply test if the encryption validates. */
                                let _ciphertext = new Buffer(
                                    encrypt(plaintext, key, mode, scheme, true, false, salt),
                                    'hex'
                                );

                                /* Then we decrypt the ciphertext. */
                                let _plaintext = decrypt(_ciphertext, key, mode, scheme, 'hex');

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

    /* Locates the given array containing the target's test vectors. */
    function locateTestVector(/* Array */ list, /* string */ name){
        for(let i = 0; i < list.length; i++){
            if(list[i].full_name.toLowerCase() === name.toLowerCase())
                return list[i];
        }

        return null;
    }

    /* Quick sanity check. */
    if(typeof preferred_cipher !== 'string')
        preferred_cipher = 'Running all cipher tests';

    /* Fetch all test vectors. */
    let aes_vectors = locateTestVector(vectors, 'aes-256'),
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

/* Load the plugin from module exports. */
function loadDiscordCrypt(){
    let load = require('../src/discordCrypt.plugin.js');

    return {'class': load, 'instance': new load()};
}

/* Generates cipher test vectors. */
function generateCipherTests(/* Object */ loaded_blob, /* int */ num_tests = 25){
    const ciphers = [
        {
            full_name: 'AES-256',
            name: 'aes-256',
            block_size: 16,
            key_size: 32,
            encryptor: loaded_blob['class'].aes256_encrypt,
            decryptor: loaded_blob['class'].aes256_decrypt,
        },
        {
            full_name: 'Camellia-256',
            name: 'camellia-256',
            block_size: 16,
            key_size: 32,
            encryptor: loaded_blob['class'].camellia256_encrypt,
            decryptor: loaded_blob['class'].camellia256_decrypt,
        },
        {
            full_name: 'TripleDES-192',
            name: 'tripledes-192',
            block_size: 8,
            key_size: 24,
            encryptor: loaded_blob['class'].tripledes192_encrypt,
            decryptor: loaded_blob['class'].tripledes192_decrypt,
        },
        {
            full_name: 'IDEA-128',
            name: 'idea-128',
            block_size: 8,
            key_size: 16,
            encryptor: loaded_blob['class'].idea128_encrypt,
            decryptor: loaded_blob['class'].idea128_decrypt,
        },
        {
            full_name: 'Blowfish-512',
            name: 'blowfish-512',
            block_size: 8,
            key_size: 64,
            encryptor: loaded_blob['class'].blowfish512_encrypt,
            decryptor: loaded_blob['class'].blowfish512_decrypt
        }
    ];
    const block_modes = [
        'cbc',
        'cfb',
        'ofb'
    ];
    const padding_schemes = [
        'PKC7',
        'ANS2',
        'ISO9',
        'ZR0',
        'ISO1',
    ];

    const process = require('process');
    const crypto = require('crypto');

    let unit_tests = [];

    for(let i = 0; i < ciphers.length; i++){

        unit_tests[i] = {};

        unit_tests[i].full_name = ciphers[i].full_name;
        unit_tests[i].name = ciphers[i].name;

        unit_tests[i].tests = [];

        for(let j = 0; j < block_modes.length; j++){

            unit_tests[i].tests[j] = [];

            for(let k = 0; k < padding_schemes.length; k++){

                unit_tests[i].tests[j][k] = {};
                unit_tests[i].tests[j][k].mode = block_modes[j];
                unit_tests[i].tests[j][k].scheme = padding_schemes[k];
                unit_tests[i].tests[j][k].r = [];

                for(let l = 0; l < num_tests; l++){
                    let plaintext = crypto.randomBytes((ciphers[i].key_size * (l + 1)) + (l + k + i));
                    let key = crypto.randomBytes(ciphers[i].key_size);
                    let salt = crypto.randomBytes(8);

                    /* Quick sanity check for Zero-Padding which can't end in zeros. */
                    if(padding_schemes[k].toLowerCase() === 'ZR0'){
                        do plaintext[plaintext.length - 1] = crypto.randomBytes(1)[0];
                        while(plaintext[plaintex.length - 1] === 0)
                    }

                    let ciphertext = ciphers[i].encryptor(
                        plaintext,
                        key,
                        unit_tests[i].tests[j][k].mode,
                        unit_tests[i].tests[j][k].scheme,
                        true,
                        false,
                        salt
                    );

                    let _plaintext = ciphers[i].decryptor(
                        ciphertext,
                        key,
                        unit_tests[i].tests[j][k].mode,
                        unit_tests[i].tests[j][k].scheme,
                        'hex',
                        true
                    );

                    if(_plaintext !== plaintext.toString('hex')){
                        l--;
                        console.log(`Invalid test generated for ${ciphers[i].name}.`);
                        continue;
                    }

                    unit_tests[i].tests[j][k].r[l] = {};

                    unit_tests[i].tests[j][k].r[l].plaintext = plaintext.toString('hex');
                    unit_tests[i].tests[j][k].r[l].ciphertext = ciphertext;

                    unit_tests[i].tests[j][k].r[l].key = key.toString('hex');
                    unit_tests[i].tests[j][k].r[l].salt = salt.toString('hex');
                }
            }
        }
    }

    require('fs').writeFileSync('./tests/cipher-test-vectors.json', JSON.stringify(unit_tests, undefined, ' '));
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
            default:
                throw 'Executing all tests.';
        }
    }
    catch(e){
        /* Run Scrypt tests. */
        addScryptTests(loaded_blob, unit_tests);

        /* Run Hash/PBKDF2 tests. */
        addPBKDF2Tests(loaded_blob, unit_tests);

        /* Run cipher tests. */
        addCipherTests(loaded_blob, unit_tests);
    }

    /* Actually run all the tests. */
    nodeunit.reporters.default.run(unit_tests);
}

main();
