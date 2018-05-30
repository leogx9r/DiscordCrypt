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
    }

    /* Generates cipher test vectors. */
    generateCipherTests(/* int */ num_tests = 25, /* string */ output_path = './tests/cipher-test-vectors.json'){
        const ciphers = [
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
                        let plaintext = this.crypto.randomBytes((ciphers[i].key_size * (l + 1)) + (l + k + i));
                        let key = this.crypto.randomBytes(ciphers[i].key_size);
                        let salt = this.crypto.randomBytes(8);

                        /* Quick sanity check for Zero-Padding which can't end in zeros. */
                        if(padding_schemes[k].toLowerCase() === 'ZR0'){
                            do plaintext[plaintext.length - 1] = this.crypto.randomBytes(1)[0];
                            while(plaintext[plaintex.length - 1] === 0)
                        }

                        let ciphertext = ciphers[i].encrypt(
                            plaintext,
                            key,
                            unit_tests[i].tests[j][k].mode,
                            unit_tests[i].tests[j][k].scheme,
                            true,
                            false,
                            salt
                        );

                        let _plaintext = ciphers[i].decrypt(
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

        this.fs.writeFileSync(output_path, JSON.stringify(unit_tests, undefined, ' '));
    }
}

module.exports = testGenerator;
