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

/* Generates test vectors. */
class testGenerator
{
    /* Loads required modules. */
    constructor(){
        this.fs = require('fs');
        this.crypto = require('crypto');
        this.discordCrypt = require('../src/discordCrypt.plugin.js');

        this.ciphers = [
            {
                full_name: 'AES-256',
                name: 'aes-256',
                block_size: 16,
                key_size: 32,
                encrypt: this.discordCrypt.aes256_encrypt,
                decrypt: this.discordCrypt.aes256_decrypt,
            },
            {
                full_name: 'Camellia-256',
                name: 'camellia-256',
                block_size: 16,
                key_size: 32,
                encrypt: this.discordCrypt.camellia256_encrypt,
                decrypt: this.discordCrypt.camellia256_decrypt,
            },
            {
                full_name: 'TripleDES-192',
                name: 'tripledes-192',
                block_size: 8,
                key_size: 24,
                encrypt: this.discordCrypt.tripledes192_encrypt,
                decrypt: this.discordCrypt.tripledes192_decrypt,
            },
            {
                full_name: 'IDEA-128',
                name: 'idea-128',
                block_size: 8,
                key_size: 16,
                encrypt: this.discordCrypt.idea128_encrypt,
                decrypt: this.discordCrypt.idea128_decrypt,
            },
            {
                full_name: 'Blowfish-512',
                name: 'blowfish-512',
                block_size: 8,
                key_size: 64,
                encrypt: this.discordCrypt.blowfish512_encrypt,
                decrypt: this.discordCrypt.blowfish512_decrypt
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
            'ZR0',
            'ISO1',
        ];
    }

    /* Generates individual tests for each cipher mode and padding scheme. */
    addCipherTest(/* int */ num_tests = 25, /* Array */ unit_tests, /* int */ i, /* int */ j, /* int */ k){
        /* Loop for the number of tests desired. */
        for(let l = 0; l < num_tests; l++){
            /* Generate random plaintext. */
            let plaintext = this.crypto.randomBytes((this.ciphers[i].key_size * (l + 1)) + (l + k + i));

            /* Generate a random key and one-time salt. */
            let key = this.crypto.randomBytes(this.ciphers[i].key_size);
            let salt = this.crypto.randomBytes(8);

            /* Quick sanity check for Zero-Padding which can't end in zeros. */
            if(this.padding_schemes[k].toLowerCase() === 'ZR0'){
                do plaintext[plaintext.length - 1] = this.crypto.randomBytes(1)[0];
                while(plaintext[plaintex.length - 1] === 0)
            }

            /* Perform a round of encryption. */
            let ciphertext = this.ciphers[i].encrypt(
                plaintext,
                key,
                unit_tests[i].tests[j][k].mode,
                unit_tests[i].tests[j][k].scheme,
                true,
                false,
                salt
            );

            /* Perform a round of decryption. */
            let _plaintext = this.ciphers[i].decrypt(
                ciphertext,
                key,
                unit_tests[i].tests[j][k].mode,
                unit_tests[i].tests[j][k].scheme,
                'hex',
                true
            );

            /* Make sure that the plaintext generated matches the decrypted value. */
            if(_plaintext !== plaintext.toString('hex')){
                l--;
                console.log(`Invalid test generated for ${this.ciphers[i].name}.`);
                continue;
            }

            /* Store the test result. */
            unit_tests[i].tests[j][k].r[l] = {};

            unit_tests[i].tests[j][k].r[l].plaintext = plaintext.toString('hex');
            unit_tests[i].tests[j][k].r[l].ciphertext = ciphertext;

            unit_tests[i].tests[j][k].r[l].key = key.toString('hex');
            unit_tests[i].tests[j][k].r[l].salt = salt.toString('hex');
        }
    }

    /* Generates cipher test vectors. */
    generateCipherTests(/* int */ num_tests = 25, /* string */ output_path = './tests/cipher-test-vectors.json'){

        let unit_tests = [];

        for(let i = 0; i < this.ciphers.length; i++){

            unit_tests[i] = {};

            unit_tests[i].full_name = this.ciphers[i].full_name;
            unit_tests[i].name = this.ciphers[i].name;

            unit_tests[i].tests = [];

            for(let j = 0; j < this.block_modes.length; j++){

                unit_tests[i].tests[j] = [];

                for(let k = 0; k < this.padding_schemes.length; k++){

                    unit_tests[i].tests[j][k] = {};
                    unit_tests[i].tests[j][k].mode = this.block_modes[j];
                    unit_tests[i].tests[j][k].scheme = this.padding_schemes[k];
                    unit_tests[i].tests[j][k].r = [];

                    this.addCipherTest(num_tests, unit_tests, i, j, k);
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
        aes_gcm.tests[0] = [];

        /* Loop over all padding schemes. */
        for(let k = 0; k < this.padding_schemes.length; k++){
            aes_gcm.tests[0][k] = {};
            aes_gcm.tests[0][k].mode = 'gcm';
            aes_gcm.tests[0][k].scheme = this.padding_schemes[k];

            aes_gcm.tests[0][k].r = [];

            /* Generate each test. */
            for(let l = 0; l < num_tests; l++){
                /* Generate random plaintext. */
                let plaintext = this.crypto.randomBytes((32 * (l + 1)) + (l + k + this.ciphers.length));

                /* Generate a random key and one-time salt. */
                let key = this.crypto.randomBytes(32);
                let salt = this.crypto.randomBytes(8);

                /* Quick sanity check for Zero-Padding which can't end in zeros. */
                if(this.padding_schemes[k].toLowerCase() === 'ZR0'){
                    do plaintext[plaintext.length - 1] = this.crypto.randomBytes(1)[0];
                    while(plaintext[plaintex.length - 1] === 0)
                }

                /* Perform a round of encryption. */
                let ciphertext = this.discordCrypt.aes256_encrypt_gcm(
                    plaintext,
                    key,
                    this.padding_schemes[k],
                    true,
                    false,
                    undefined,
                    salt
                );

                /* Perform a round of decryption. */
                let _plaintext = this.discordCrypt.aes256_decrypt_gcm(
                    ciphertext,
                    key,
                    this.padding_schemes[k],
                    'hex',
                    true
                );

                /* Make sure that the plaintext generated matches the decrypted value. */
                if(_plaintext !== plaintext.toString('hex')){
                    l--;
                    console.log(`Invalid test generated for ${this.ciphers[i].name}.`);
                    continue;
                }

                /* Store the test result. */
                aes_gcm.tests[0][k].r[l] = {};

                aes_gcm.tests[0][k].r[l].plaintext = plaintext.toString('hex');
                aes_gcm.tests[0][k].r[l].ciphertext = ciphertext;

                aes_gcm.tests[0][k].r[l].key = key.toString('hex');
                aes_gcm.tests[0][k].r[l].salt = salt.toString('hex');
            }
        }

        unit_tests[this.ciphers.length] = aes_gcm;

        this.fs.writeFileSync(output_path, JSON.stringify(unit_tests, undefined, ' '));
    }
}

module.exports = testGenerator;
