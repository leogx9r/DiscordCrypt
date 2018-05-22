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
     * ✔ Test #0: [ N: 16 p: 1 r: 1 ]
     * ✔ Test #1: [ N: 1024 p: 16 r: 8 ]
     * ✔ Test #2: [ N: 16384 p: 1 r: 8 ]
     * ✔ Test #3: [ N: 1048576 p: 1 r: 8 ]
     * ✔ Test #4: [ N: 262144 p: 1 r: 8 ]
     */

    /* Prepare the unit tests. */
    unit_tests.discordCrypt_scrypt = {};

    /* Loop over all tests. */
    for (let i = 0; i < vectors.length; i++){
        let v = vectors[i],
            k = `Test #${Object.keys(unit_tests.discordCrypt_scrypt).length}: [ N: ${v.N} p: ${v.p} r: ${v.r} ]`;

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
     * ✔ sha1: Test #0
     * ✔ sha1: Test #1
     * ✔ sha1: Test #2
     * ✔ sha1: Test #3
     * ✔ sha1: Test #4
     * ✔ sha1: Test #5
     * ✔ sha1: Test #6
     * ✔ sha1: Test #7
     * ✔ sha256: Test #8
     * ✔ sha256: Test #9
     * ✔ sha256: Test #10
     * ✔ sha256: Test #11
     * ✔ sha256: Test #12
     * ✔ sha256: Test #13
     * ✔ sha256: Test #14
     * ✔ sha256: Test #15
     * ✔ sha512: Test #16
     * ✔ sha512: Test #17
     * ✔ sha512: Test #18
     * ✔ sha512: Test #19
     * ✔ sha512: Test #20
     * ✔ sha512: Test #21
     * ✔ sha512: Test #22
     * ✔ sha512: Test #23
     * ✔ whirlpool: Test #24
     * ✔ whirlpool: Test #25
     * ✔ whirlpool: Test #26
     * ✔ whirlpool: Test #27
     * ✔ whirlpool: Test #28
     * ✔ whirlpool: Test #29
     * ✔ whirlpool: Test #30
     * ✔ whirlpool: Test #31
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

/* Load the plugin by simply doing an eval() */
function loadDiscordCrypt(){
    let load = eval(`( ${require("fs").readFileSync('src/discordCrypt.plugin.js').toString()} )`);

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
            default:
                throw 'Executing all tests.';
        }
    }
    catch(e){
        /* Run Scrypt tests. */
        addScryptTests(loaded_blob, unit_tests);

        /* Run Hash/PBKDF2 tests. */
        addPBKDF2Tests(loaded_blob, unit_tests);
    }

    /* Actually run all the tests. */
    nodeunit.reporters.default.run(unit_tests);
}

main();
