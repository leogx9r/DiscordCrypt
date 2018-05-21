/* Reference: https://tools.ietf.org/html/rfc7914#page-13 */
const vectors = require('./scrypt-test-vectors');

/* Required for unit tests. */
const nodeunit = require('nodeunit');

/* Load the plugin by simply doing an eval() */
function loadDiscordCrypt(){
    let load = eval(`( ${require("fs").readFileSync('src/discordCrypt.plugin.js').toString()} )`);

    return {'class': load, 'instance': new load()};
}

/* Create a test unit. */
function createTest(
    /* Array */ vector,
    /* function(pwd, salt, hashSize, N, r, p, function(error, progress, key)) */ scrypt
){
    /* Convert the password and salt to Buffer objects. */
    let password = new Buffer(vector.password, 'hex');
    let salt = new Buffer(vector.salt, 'hex');

    /* Save the key. */
    let derivedKey = vector.derivedKey;

    /* Return the method that actually runs the test. */
    return function (ut) {
        /* Passed from the loaded class file. */
        scrypt(password, salt, vector.dkLen, vector.N, vector.r, vector.p, (error, progress, key) => {
            /* On errors, let the user know. */
            if (error){
                console.log(error);
                return;
            }

            /* Once the key has been calculated, check it. */
            if (key) {
                ut.equal(derivedKey, key.toString('hex'),
                    `Scrypt Test Failed. ( Expected: ${derivedKey} | Got: ${key.toString('hex')} )`);
                ut.done();
            }
        });
    }
}

function main(){
    /* Actually load the plugin. */
    let loaded_blob = loadDiscordCrypt();

    /* Prepare the unit tests. */
    let unit_tests = {discordCrypt_scrypt: {}};

    /* Loop over all tests. */
    for (let i = 0; i < vectors.length; i++){
        let v = vectors[i],
            k = `Test #${Object.keys(unit_tests.discordCrypt_scrypt).length}: [ N: ${v.N} p: ${v.p} r: ${v.r} ]`;

        /* Create a function callback for this test name. */
        unit_tests.discordCrypt_scrypt[k] = createTest(v, loaded_blob['class'].scrypt, i);
    }

    /* Actually run all the tests. */
    nodeunit.reporters.default.run(unit_tests);
}

/**
 * Expected Results:
 *
 * discordCrypt_scrypt
 * ✔ Test #0: [ N: 16 p: 1 r: 1 ]
 * ✔ Test #1: [ N: 1024 p: 16 r: 8 ]
 * ✔ Test #2: [ N: 16384 p: 1 r: 8 ]
 * ✔ Test #3: [ N: 1048576 p: 1 r: 8 ]
 * ✔ Test #4: [ N: 262144 p: 1 r: 8 ]
 *
 * OK: 5 assertions (14334ms)
 */
main();
