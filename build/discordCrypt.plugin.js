//META{"name":"discordCrypt"}*//

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

"use strict";

/**
 * @public
 * @desc Main plugin prototype.
 */
class discordCrypt
{

    /* ========================================================= */

    /**
     * @typedef {Object} WebpackModuleSearcher
     * @desc Returns various functions that can scan for webpack modules.
     * @property {function(function(module : Object))} find Recursively iterates all webpack modules to
     *      the callback function.
     * @property {function(prototypes: string[])} findByUniquePrototypes Iterates all modules looking for the
     *      defined prototypes.
     * @property {function(properties: string[])} findByUniqueProperties Iterates all modules look for the
     *      defined properties.
     * @property {function(displayName: string)} findByDisplayName Iterates all modules looking for the specified
     *      display name.
     * @property {function(id: int)} findByDispatchToken Iterates all modules looking for the specified dispatch
     *      token by its ID.
     * @property {function(dispatchNames: string[])} findByDispatchNames Iterates all modules looking for the specified
     *      dispatch names.
     */

    /**
     * @typedef {Object} CachedModules
     * @desc Cached React and Discord modules for internal access.
     * @property {Object} MessageParser Internal message parser that's used to translate tags to Discord symbols.
     * @property {Object} MessageController Internal message controller used to receive, send and delete messages.
     * @property {Object} MessageActionTypes Internal message action types and constants for events.
     * @property {Object} MessageDispatcher Internal message dispatcher for pending queued messages.
     * @property {Object} MessageQueue Internal message Queue store for pending parsing.
     * @property {Object} UserResolver Internal user resolver for retrieving all users known.
     * @property {Object} GuildResolver Internal Guild resolver for retrieving a list of all guilds currently in.
     * @property {Object} ChannelResolver Internal channel resolver for retrieving a list of all channels available.
     * @property {Object} HighlightJS Internal code based library responsible for highlighting code blocks.
     */

    /**
     * @typedef {Object} ReactModules
     * @desc Contains all React and Discord modules including the channel's properties for internal access.
     * @property {Object} ChannelProps Retrieved channel properties object for the current channel.
     * @property {Object} MessageParser Internal message parser that's used to translate tags to Discord symbols.
     * @property {Object} MessageController Internal message controller used to receive, send and delete messages.
     * @property {Object} MessageActionTypes Internal message action types and constants for events.
     * @property {Object} MessageDispatcher Internal message dispatcher for pending queued messages.
     * @property {Object} MessageQueue Internal message Queue store for pending parsing.
     * @property {Object} UserResolver Internal user resolver for retrieving all users known.
     * @property {Object} GuildResolver Internal Guild resolver for retrieving a list of all guilds currently in.
     * @property {Object} ChannelResolver Internal channel resolver for retrieving a list of all channels available.
     * @property {Object} HighlightJS Internal code based library responsible for highlighting code blocks.
     */

    /**
     * @typedef {Object} TimedMessage
     * @desc Contains a timed message pending deletion.
     * @property {string} messageId The identification tag of the timed message.
     * @property {string} channelId The channel's identifier that this message was sent to.
     * @property {Date} expireTime The time to purge the message from the channel.
     */

    /**
     * @typedef {Object} ChannelPassword
     * @desc Contains the primary and secondary keys used to encrypt or decrypt messages in a channel.
     * @property {string} primary The primary key used for the inner cipher.
     * @property {string} secondary The secondary key used for the outer cipher.
     */

    /**
     * @typedef {Object} PublicKeyInfo
     * @desc Contains information given an input public key.
     * @property {string} fingerprint The SHA-256 sum of the public key.
     * @property {string} algorithm The public key's type ( DH | ECDH ) extracted from the metadata.
     * @property {int} bit_length The length, in bits, of the public key's security.
     */

    /**
     * @typedef {Object} Config
     * @desc Contains the configuration data used for the plugin.
     * @property {string} version The version of the configuration.
     * @property {boolean} useEmbeds Whether to use embeds for dispatching encrypted messages.
     * @property {string} defaultPassword The default key to encrypt or decrypt message with,
     *      if not specifically defined.
     * @property {string} encodeMessageTrigger The suffix trigger which, once appended to the message,
     *      forces encryption even if a key is not specifically defined for this channel.
     * @property {number} encryptScanDelay If using timed scanning events in case hooked events fail,
     *      this denotes how often, in milliseconds, to scan the window for new messages and decrypt them.
     * @property {number} encryptMode The index of the ciphers to use for message encryption.
     * @property {string} encryptBlockMode The block operation mode of the ciphers used to encrypt message.
     * @property {boolean} encodeAll If enabled, automatically forces all messages sent to be encrypted if a
     *      ChannelPassword object is defined for the current channel..
     * @property {string} paddingMode The short-hand padding scheme to used to align all messages to the cipher's
     *      block length.
     * @property {{channelId: string, password: ChannelPassword}} passList Storage containing all channels with
     *      passwords defined for encryption of new messages and decryption of currently encrypted messages.
     * @property {string} up1Host The full URI host of the Up1 service to use for encrypted file uploads.
     * @property {string} up1ApiKey If specified, contains the API key used for authentication with the up1Host.
     * @property {Array<TimedMessage>} timedMessages Contains all logged timed messages pending deletion.
     * @property {number} timedMessageExpires How long after a message is sent should it be deleted in seconds.
     */

    /**
     * @typedef {Object} UpdateCallback
     * @desc The function to execute after an update has been retrieved.
     * @property {string} file_data The update file's data.
     * @property {string} short_hash A 64-bit SHA-256 checksum of the new update.
     * @property {string} new_version The new version of the update.
     * @property {string} full_changelog The full changelog.
     * @property {boolean} Whether the PGP signature is valid or not.
     */

    /**
     * @typedef {Object} ModulePredicate
     * @desc Predicate for searching module.
     * @property {*} module Module to test.
     * @return {boolean} Returns `true` if `module` matches predicate.
     */

    /**
     * @typedef {Object} GetResultCallback
     * @desc The function to execute at the end of a GET request containing the result or error that occurred.
     * @property {int} statusCode The HTTP static code of the operation.
     * @property {string|null} The HTTP error string if an error occurred.
     * @property {string} data The returned data from the request.
     * @return {boolean} Returns true if the data was parsed sucessfully.
     */

    /**
     * @typedef {Object} CodeBlockDescriptor
     * @desc Indicates the values present in a markdown-styled code block.
     * @property {int} start_pos The starting position of the code block.
     * @property {int} end_pos The ending position of the code block.
     * @property {string} language The language identifier of the code within this block.
     * @property {string} raw_code The raw code within the code block.
     * @property {string} captured_block The entire markdown formatted code block.
     */

    /**
     * @typedef {Object} PBKDF2Callback
     * @desc The function to execute after an async request for PBKDF2 is completed containing the result or error.
     * @property {string} error The error that occurred during processing or null on success.
     * @property {string} hash The hash either as a hex or Base64 encoded string ( or null on failure ).
     */

    /**
     * @typedef {Object} EncryptedFileCallback
     * @desc The function to execute when a file has finished being encrypted.
     * @property {string} error_string The error that occurred during operation or null if no error occurred.
     * @property {Buffer} encrypted_data The resulting encrypted buffer as a Buffer() object.
     * @property {string} identity The encoded identity of the encrypted file.
     * @property {string} seed The initial seed used to decrypt the encryption keys of the file.
     */

    /**
     * @typedef {Object} UploadedFileCallback
     * @desc The function to execute after a file has been uploaded to an Up1 service.
     * @property {string} error_string The error that occurred or null if no error occurred.
     * @property {string} file_url The URL of the uploaded file/
     * @property {string} deletion_link The link used to delete the file.
     * @property {string} encoded_seed The encoded encryption key used to decrypt the file.
     */

    /**
     * @typedef {Object} ScryptCallback
     * @desc The function to execute for Scrypt based status updates.
     *      The function must return false repeatedly upon each call to have Scrypt continue running.
     *      Once [progress] === 1.f AND [key] is defined, no further calls will be made.
     * @property {string} error The error message encountered or null.
     * @property {real} progress The percentage of the operation completed. This ranges from [ 0.00 - 1.00 ].
     * @property {Buffer} result The output result when completed or null if not completed.
     * @returns {boolean} Returns false if the operation is to continue running or true if the cancel the running
     *      operation.
     */

    /**
     * @typedef {Object} HashCallback
     * @desc The function to execute once the hash is calculated or an error has occurred.
     * @property {string} error The error that occurred or null.
     * @property {string} hash The hex or Base64 encoded result.
     */

    /**
     * @typedef {Object} ClipboardInfo
     * @desc Contains extracted data from the current clipboard.
     * @property {string} mime_type The MIME type of the extracted data.
     * @property {string|null} name The name of the file, if a file was contained in the clipboard.
     * @property {Buffer|null} data The raw data contained in the clipboard as a Buffer.
     */

    /**
     * @typedef {Object} ProcessedMessage
     * @desc Contains a processed message with additional data.
     * @property {boolean} url Whether the message has any parsed URLs within it.
     * @property {boolean} code Whether the message has any parsed code blocks within it.
     * @property {string} html The raw message's HTML.
     */

    /**
     * @typedef {Object} UserTags
     * @desc Extracted user tagging information from an input message.
     * @property {string} processed_message The processed message containing user tags with the discriminator removed.
     * @property {Array<string>} user_tags All extracted user tags from the message.
     */

    /**
     * @typedef {Object} URLInfo
     * @desc Contains information of a message containing any URLs.
     * @property {boolean} url Whether the input message contained any parsed URLs.
     * @property {string} html The raw formatted HTML containing any parsed URLs.
     */

    /**
     * @typedef {Object} CodeBlockInfo
     * @desc Contains information of a message containing code blocks.
     * @property {boolean} code Whether the input message contained any parsed code blocks.
     * @property {string} html The raw formatted HTML containing any parsed code blocks.
     */

    /**
     * @typedef {Object} LibraryInfo
     * @desc Contains the library and necessary information.
     * @property {boolean} requiresElectron Whether this library relies on Electron's internal support.
     * @property {boolean} requiresBrowser Whether this library is meant to be run in a browser.
     * @property {string} code The raw code for execution defined in the library.
     */

    /**
     * @typedef {Object} LibraryDefinition
     * @desc Contains a definition of a raw library executed upon plugin startup.
     * @property {string} name The name of the library file.
     * @property {LibraryInfo} info The library info.
     */

    /* ========================================================= */

    /**
     * @public
     * @desc Initializes an instance of DiscordCrypt.
     * @example
     * let instance = new discordCrypt();
     */
    constructor() {

        /* ============================================ */

        /**
         * Discord class names that changes ever so often because they're douches.
         * These will usually be the culprit if the plugin breaks.
         */

        /**
         * @desc Used to scan each message for an embedded descriptor.
         * @type {string}
         */
        this.messageMarkupClass = '.markup';
        /**
         * @desc Used to find the search toolbar to inject all option buttons.
         * @type {string}
         */
        this.searchUiClass = '.search .search-bar';
        /**
         * @desc Used to hook messages being sent.
         * @type {string}
         */
        this.channelTextAreaClass = '.content textarea';
        /**
         * @desc Used to detect if the autocomplete dialog is opened.
         * @type {string}
         */
        this.autoCompleteClass = '.autocomplete-1vrmpx';

        /* ============================================ */

        /**
         * @desc Defines what an encrypted message starts with. Must be 4x UTF-16 bytes.
         * @type {string}
         */
        this.encodedMessageHeader = "⢷⢸⢹⢺";

        /**
         * @desc Defines what a public key message starts with. Must be 4x UTF-16 bytes.
         * @type {string}
         */
        this.encodedKeyHeader = "⢻⢼⢽⢾";

        /**
         * @desc Defines what the header of an encrypted message says.
         * @type {string}
         */
        this.messageHeader = '-----ENCRYPTED MESSAGE-----';

        /**
         * @desc Master database password. This is a Buffer() containing a 256-bit key.
         * @type {Buffer|null}
         */
        this.masterPassword = null;

        /**
         * @desc Message scanning interval handler's index. Used to stop any running handler.
         *      Defined only if hooking of modules failed.
         * @type {int}
         */
        this.scanInterval = undefined;

        /**
         * @desc The index of the handler used to reload the toolbar.
         *      Defined only if hooking of modules failed.
         * @type {int}
         */
        this.toolbarReloadInterval = undefined;

        /**
         * @desc The index of the handler used for automatic update checking.
         * @type {int}
         */
        this.updateHandlerInterval = undefined;

        /**
         * @desc The index of the handler used for timed message deletion.
         * @type {int}
         */
        this.timedMessageInterval = undefined;

        /**
         * @desc The main message update event dispatcher used by Discord. Resolved upon startup.
         * @type {Object|null}
         */
        this.messageUpdateDispatcher = null;

        /**
         * @desc The configuration file currently in use. Only valid after decryption of the configuration database.
         * @type {Config|null}
         */
        this.configFile = null;

        /**
         * @desc Used to cache webpack modules.
         * @type {CachedModules} Object containing cached modules
         */
        this.cachedModules = {};

        /**
         * @desc Indexes of each dual-symmetric encryption mode.
         * @type {int[]}
         */
        this.encryptModes = [
            /* Blowfish(Blowfish, AES, Camellia, IDEA, TripleDES) */
            0, 1, 2, 3, 4,
            /* AES(Blowfish, AES, Camellia, IDEA, TripleDES) */
            5, 6, 7, 8, 9,
            /* Camellia(Blowfish, AES, Camellia, IDEA, TripleDES) */
            10, 11, 12, 13, 14,
            /* IDEA(Blowfish, AES, Camellia, IDEA, TripleDES) */
            15, 16, 17, 18, 19,
            /* TripleDES(Blowfish, AES, Camellia, IDEA, TripleDES) */
            20, 21, 22, 23, 24
        ];

        /**
         * @desc Symmetric block modes of operation.
         * @type {string[]}
         */
        this.encryptBlockModes = [
            'CBC', /* Cipher Block-Chaining */
            'CFB', /* Cipher Feedback Mode */
            'OFB', /* Output Feedback Mode */
        ];

        /**
         * @desc Shorthand padding modes for block ciphers referred to in the code.
         * @type {string[]}
         */
        this.paddingModes = [
            'PKC7', /* PKCS #7 */
            'ANS2', /* ANSI X.923 */
            'ISO1', /* ISO-10126 */
            'ISO9', /* ISO-97972 */
        ];

        /**
         * @desc Defines the CSS for the application overlays.
         * @type {string}
         */
        this.appCss =
            `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`;

        /**
         * @desc Contains the raw HTML used to inject into the search descriptor providing menu icons.
         * @type {string}
         */
        this.toolbarHtml =
            `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`;

        /**
         * @desc Contains the raw HTML injected into the overlay to prompt for the master password for database
         *      unlocking.
         * @type {string}
         */
        this.masterPasswordHtml =
            `eNqtUs1uwyAMfhWLqUeUrLt1aS7bA+wVHKANGgUETqu+/SAJSVpNO42DY9n+fjBppL6ClkcmBb9gJBW4u6pg8M5AGIxx7JRSC81mfq5yoWzCnbQy8hfQYzvS3agjI+cP8FbvEiM0/b6UhTMuHF5Opzqdd1aEeoUyGZv9XeKZtU3V7zO2C1U7hpRHj7ZAfHAXT0+QPLBMa+sHArr7pOuT55sLD/ZLjc/OZ2LZ8XWaNGXbn0jYYVTwVTpV8QbTxmbaSEiQA+8w5LsvpuEImyfII0NkW1hG8ICk7XnZ4k1L6g+QNjUKVUnpSTBRhsEkRjT6bCfFbiBydjMxFZ5YX+t6t77AYI0T31zOF+Ud2f/QhCXj2qbfJSoG+fzhRKAVyowG2o8xb6qJYrUzfab4AyMh9Dk=`;

        /**
         * @desc Defines the raw HTML used describing each option menu.
         * @type {string}
         */
        this.settingsMenuHtml =
            `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`;

        /**
         * @desc The Base64 encoded SVG containing the unlocked status icon.
         * @type {string}
         */
        this.unlockIcon = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwIDI0I" +
            "DI0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMTdjMS4xIDAgMi0u" +
            "OSAyLTJzLS45LTItMi0yLTIgLjktMiAyIC45IDIgMiAyem02LTloLTFWNmMwLTIuNzYtMi4yNC01LTUtNVM3IDMuMjQgNyA2aDEuOWM" +
            "wLTEuNzEgMS4zOS0zLjEgMy4xLTMuMSAxLjcxIDAgMy4xIDEuMzkgMy4xIDMuMXYySDZjLTEuMSAwLTIgLjktMiAydjEwYzAgMS4xLj" +
            "kgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6bTAgMTJINlYxMGgxMnYxMHoiPjwvcGF0aD48L3N2Zz4=";

        /**
         * @desc The Base64 encoded SVG containing the locked status icon.
         * @type {string}
         */
        this.lockIcon = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwIDI0IDI" +
            "0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZGVmcz48cGF0aCBkPSJNMCAwaDI0djI0SD" +
            "BWMHoiIGlkPSJhIi8+PC9kZWZzPjxjbGlwUGF0aCBpZD0iYiI+PHVzZSBvdmVyZmxvdz0idmlzaWJsZSIgeGxpbms6aHJlZj0iI2EiL" +
            "z48L2NsaXBQYXRoPjxwYXRoIGNsaXAtcGF0aD0idXJsKCNiKSIgZD0iTTEyIDE3YzEuMSAwIDItLjkgMi0ycy0uOS0yLTItMi0yIC45" +
            "LTIgMiAuOSAyIDIgMnptNi05aC0xVjZjMC0yLjc2LTIuMjQtNS01LTVTNyAzLjI0IDcgNnYySDZjLTEuMSAwLTIgLjktMiAydjEwYzA" +
            "gMS4xLjkgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6TTguOSA2YzAtMS43MSAxLjM5LTMuMSAzLjEtMy" +
            "4xczMuMSAxLjM5IDMuMSAzLjF2Mkg4LjlWNnpNMTggMjBINlYxMGgxMnYxMHoiLz48L3N2Zz4=";

        /**
         * @desc These contain all libraries that will be loaded dynamically in the current JS VM.
         * @type {LibraryDefinition}
         */
        this.libraries = {
            'currify.js': {"requiresElectron":false,"requiresBrowser":true,"minify":true,"code":"eNqdVFFv2yAQ/iuONaWgEit5jUujae2etvZlfbKs1rWhYaLgYWgWOfz3gcFOKuWh3Ys5HXcfd9995xk1otZMCiBgzyhI5fNvUusUY71viaQJ+dtKpbv5PDWiIZQJ0qSz8fJVNoYTGI4shmIBYE54RxKPN+IfEQPKfB7OrHptYDBBUSIRUntOdKJyoPC5Z3dMNHK3Ccf6XMQLl88V34TjbERHON34z1pvWQez2ijF6N4Xby2YWIH9W6USgRQiuSLaKJGMd4kAzos07CePBBSZgccZKWgZLDVYHqbGZ+hQ5I9hyvERjdznmPm8hvG92oHOltD72ehj0edRORZkl9wqJRV4+lYJIXXimm3idJKLLz21F08w11sldwnPatkQnP68v3n4cft4d//r8fv9w91Nirj1cC32peM+TnPdW5v7FoplmdUV56AdB41OteNTCR4CV2UhypEtCcjhIKBFLTomDnw65mwM8i+Ol0MR7ENMUdexF4rAy1xc6YwT8aK3ubi8hBJoVwScqrCgjxNeF8eyfRmwT43TaqcVc7ofGNX4dMawDyDFabsRV2VV2/I9eJOsSZaoUi/mlQjduX5PXiGfjfei+mwGkv+Tg9gHskqbn0g8/iim+UwrJWBQWJBiSkXSbaXhTfJMpqWZpW7o05/iPc1+nEFG09txpIjhr0pVe0CuVxuyWK2XEFG8yumVE4GbNivoYlUe05yc/LpIh4pYxLjGKlrwfMMsrJM5VkXARI54H1sotwxS1JUGDA2lZa2SWnomso6zmoRdOZIIHfn1VMJirGqxQnwUqQYGFnV5OBhrUe9Ydx9UpFG3aQnBZEML838pAQw+"},
            'curve25519.js': {"requiresElectron":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'openpgp.js': {"requiresElectron":true,"requiresBrowser":true,"minify":false,"code":"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"},
            'sha3.js': {"requiresElectron":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sjcl.js': {"requiresElectron":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresElectron":false,"requiresBrowser":true,"minify":true,"code":"eNqtWAtb2swS/itp2q9f8hhCQLw0MfQg4l1R66319NGFLLASdmOyEZDy38/sJkC4+LTfOUcUyGYvM++8885ENY6wEvGQNLnqfNLUDkaeqpsoCDD1NHUn4kMfl82oh3yfI7878kgU+Ghot3w8cJBP2jRHOO5FdhNTjkNHjOc8EuImJ4zaTebHPeo8xxEnrWGuyWAS5ZPJPEQ0InJi0bJ6kcIC1CR86DQY56xnW46PWxw+2CsOWz7r2yjmzAmQ5xHahjXBwAlYukOLDLDnhKTdESs4C+D9LUeohwd2wbLGMyeUNSXjUcYIjACNQuRMnKSM4uw6M0BtPGqw0MNhLkQeiSN7HWxooGa3HbKYena/A3CA/YNc1EEeWGwppWCgFGGasgF/YbuBNMtQkl+zqMOnUoQbm8s3Cxu6AwCy0P64vr7u9AjN9YnHO3bJkp6nMFgzDELsI05e8dRxa/yvHvYIUhj1h0rUDDGmCqKeovXQIN1N2RDb6aMlR2cHWuMlGJSyYjZ9FuFcI4Zg0VEGBCUOfe1vD3Fkkx7MzQe0DSBFeLNkkNvd+lXfOjloswr8nH+76dRu2uJrSbzVq5VL+KgWLvEtEgM3Xb92eXtVun+5v/h+GVaOKp3K97t8+97bPj8eXLPg9iU6qHV4a+30S752dVPs5g+/ne1fBifN78f4fP/oyy62Tqtn5Hm7+X34/LxROzwirwe73f5pK2zcrx/tb1+8xL3bHt0LagdreC86IY2Lg+JxX5y+e3x1s1ELu8ftdtt1/9YVynIhDjDiSsrhDpaMK5SyXESNCIgPREjouAX3BCHFZwKonD5l52/BtTsiAzIQ5ySu9v8RZ3qT4szuLi8vN6uXlcE+7j93j7tn1eF9+/jirLtVId+bb8Nd/KNWud+snDT5wRE6X2vwNR52v/T5wWUzf9TtUHZyMHh5IXeD+rcfyEfB3f6Pzdvw6GavNojOLbRxfLX78uWU3davLFy7PGO1zgl5u+90ImoFhah6d8u2qv16q3A15Ben29WL1368e8MOTzfjNj5Zt6q3e4Xrl5Ot23zHC/Da7Xm106m/3W4P7ugwvzZg0eH+9sbW9l3+sNcs1OvV9X5vZSyXURfqBzBP1aZDPA9Th+MBz00Hse+TICKRI1M9F4FkYVCKfogCZ5ZUMqccUNcwF2Ef1FCKSTadW6CFuYi8YbtQtP5KLvsJmRrM92CvsE2oyO40zwVnlILkkjAo1RdpBWhIQahMMFh2ykxFN4dCjP7Ut8mZm5MjlyRmxUFIan5yzpLR41QmpJ8t1CP+0L5pxJTHhlIJCfINJQIhBrRC0prbfPrVyIymuwmJSjOwiHtZicS98fJ0UdcQ6L2MGIRjKT5LGeYTCitybaH2AKL2EXviZSjpF2V9+y+4kN+x7iS1wRbBAAUg3oKkW2ZxYzJpUkCKooBk64VYbC0ttLahVBAaYT4LdjKpuLFhKLM3y9ya1Y1SqSSZZRPaAWD5lFXpKdYclzJna8USHDt505extO1cj73lWqwZR6BjVMhT4ry1YjKmqOFjzxYUecWjP4B5S7wEzPLLBOYt8dKzeMmwZZ1YWbQVMzEkJ3qdYL6LWWhZQtZf6lfkFOiIfrMvyPaElxLmnGxfCtZ8WhIaxHyU1gELUn+JNB8bLfF6jyjkTWRWehNGfhtsZyFNJskpehcWcwH+EmwLgZNxNha9mL+dbaVS66RlimzunOyQLSi2BfEtlEqCtyV93hBVMJhGXNm9ub6unz/WT9wHtX6i/jSmA4/Vynm1dpqMG2pVZLUPEx4fp0Y+hrgH2uZmhxpQc7XlOTXfUGfeqfrcNhFnIXa5Wx4lRiF39Ir8GNt87ISYxyFVWjGV9NG4PkqHAPy4B+yJTB/TNu981ZApl7nc4LqdXozHzmSt8oh8HHKNG2i6yZwZHdbfA6VkbTHFUNUZGMaoKf23PxTG+ni2YRCyXiB3NLALC3w9dYHOgdLG/HoYYM3XDeZ+AyrTtoZ1EzodH6qbllfzbUP9/BIz7gA0kfu0I8OvcFjkqp9GdKwqiWtwweBC9CQ5inow8CzkASar5Sfn905FSwEGmzMOgfUtEvYSj/4pSpMdcXbHFTBwdzROgRoJF200dnlqvBqgKOoDlVXXddHX2aWtChVS398Z9wBNjhPTs5FAM6D/TQXSO42wDBmQHPi045FXpenDOa4qNEcty5F5iGW3qE6mZXtHmJ6H+eWdpLspfxrx8U4+vcjune0T1LII6qcRHqeLM/MyZV6du5GVQrWsfBr5Zg8FmuSzW37aSe4rHDVk3+t+GqHxghtgnMnZKevjsAp9rKaP1dTgZHH5STefGaGaquoT0zLvT6vRX6AEgG/QCfzMXcp0TVB81ShxPdA5kdMmPElBLGs+FleaCodDYoQgRkkegiAlETFU1hWi5FLcVy4gGwl4lSKSWoBd+vnzB2omKw3f1cS9scNAS4xIw199G+njCR0UYspqe3h9dur+jmIGMWVsziW+M3kzpn40mDdMH/erHeJ7GpmXvpaQS2I8CDcMNUnkn7rZYmENNTuQKWVuSvHX9HcWrloDUYZG5ptsvCBYV4i2MTQ7OFVK8HZuLyhXpyQCcuKw4vsaQEuaYA4xQgM2y86UoE9CbXKQYMxhHhMhBQt1sCddnNB9wAGFWP2ZNY6YcF7tFdCZHAp4ipj8t7joIg5Le6pdPIR+hapGMw6h5x3OVSW4uQc35RJdy3rwuJrj2QXLEjOqnV/XruzCulH7VrWLW8Z1Zdf+YpzW9q/t9S3j5sJe3zaujg4O4fKLsVe/O7dL1hiKgW/CxlXmYUgJfwqom/o9JXsKAGTAEkgwXZc6sEDWPUh8wUvdifqEA2YMzBX/gKFmYux7cY2MRPwN3wxCLPzdwy0U+1yDxhDSsutMtgFXlys9AIkXZwo0fDPqkBY/wcPPn7OrQK7Ah3CekdPBd23wkmv7QRVNIEAk/xUAn3EAbzLwwDric0Evt8ygmtAHIX43kIyp+GUIJTVhDpGOSJpdqYr7kmjCHij+4AdnAUgN1AokW5L3q90kBpmuhZswXuGg4aC4GJRtos/qrB8QSg1OqO9svMo0pE/Vbqo9ycNAqqGge+8ZB6Gmbp51fyV0y5scRzzpVVCqGLkC8BNgnDAS0ORfBUftyYhDWlpKU7jp//r1gcEf1RO3026TuBHs66zg8ANZUrA0vQHyZPGC+UeyxqVSj6RBlo3WCs5KzBJC/c8oZfAQ4Mg6W28JrCJ3lX0aNZioa+gh+vknbs9E7Z3QZ/V3UYT+EbVEvPJyu/mwUz0NmeJDJr8yeFxalePOquounULZmhRiL25OC3Lakhs09oEFGBTJWLX3atdTxGatO5KqhwRoLzEOh0m5Y6H29LDY9KCx+vNJ1zN6wN85ZaEUTjFe4SaeRQ4J31ZUNf+9OE4eioQwTJ55poyc94brDoJn4RDupCQ1k9VJP4HeOaGRwGWa5hQxoXFckyPj/wA0V6zy"},
        };
    }

    /* ==================== STANDARD CALLBACKS ================= */

    /**
     * @public
     * @desc Returns the name of the plugin.
     * @returns {string}
     */
    getName() {
        return 'DiscordCrypt';
    }

    /**
     * @public
     * @desc Returns the description of the plugin.
     * @returns {string}
     */
    getDescription() {
        return 'Provides secure messaging for Discord using various cryptography standards.';
    }

    /**
     * @public
     * @desc Returns the plugin's original author.
     * @returns {string}
     */
    getAuthor() {
        return 'Leonardo Gates';
    }

    /**
     * @public
     * @desc Returns the current version of the plugin.
     * @returns {string}
     */
    getVersion() {
        return '1.2.10';
    }

    /**
     * @public
     * @desc Starts the script execution. This is called by BetterDiscord if the plugin is enabled.
     */
    start() {
        /* Backup class instance. */
        const self = this;

        /* Perform idiot-proof check to make sure the user named the plugin `discordCrypt.plugin.js` */
        if ( !discordCrypt.validPluginName() ) {
            _alert(
                'Hi There! - DiscordCrypt',
                "Oops!\r\n\r\n" +
                "It seems you didn't read discordCrypt's usage guide. :(\r\n" +
                "You need to name this plugin exactly as follows to allow it to function correctly.\r\n\r\n" +
                `\t${discordCrypt.getPluginName()}\r\n\r\n\r\n` +
                "You should probably check the usage guide again just in case you missed anything else. :)"
            );
            return;
        }

        /* Perform startup and load the config file if not already loaded. */
        if ( !this.configFile ) {
            /* Load the master password. */
            this.loadMasterPassword();

            /* Don't do anything further till we have a configuration file. */
            return;
        }

        /* Don't check for updates if running a debug version. */
        if ( !discordCrypt.__shouldIgnoreUpdates( this.getVersion() ) ) {
            /* Check for any new updates. */
            this.checkForUpdates();

            /* Add an update handler to check for updates every 60 minutes. */
            this.updateHandlerInterval = setInterval( () => {
                self.checkForUpdates();
            }, 3600000 );
        }

        /* Get module searcher for caching. */
        const WebpackModules = discordCrypt.getWebpackModuleSearcher();

        /* Resolve and cache all modules needed. */
        this.cachedModules = {
            MessageParser: WebpackModules
                .findByUniqueProperties( [ 'createMessage', 'parse', 'unparse' ] ),
            MessageController: WebpackModules
                .findByUniqueProperties( [ "sendClydeError", "sendBotMessage" ] ),
            MessageActionTypes: WebpackModules
                .findByUniqueProperties( [ "ActionTypes", "ActivityTypes" ] ),
            MessageDispatcher: WebpackModules
                .findByUniqueProperties( [ "dispatch", "maybeDispatch", "dirtyDispatch" ] ),
            MessageQueue: WebpackModules
                .findByUniqueProperties( [ "enqueue", "handleSend", "handleResponse" ] ),
            UserResolver: WebpackModules
                .findByUniqueProperties( [ "getUser", "getUsers", "findByTag" ] ),
            GuildResolver: WebpackModules
                .findByUniqueProperties( [ "getGuild", "getGuilds" ] ),
            ChannelResolver: WebpackModules
                .findByUniqueProperties( [ "getChannel", "getChannels", "getDMFromUserId", 'getDMUserIds' ] ),
            HighlightJS: WebpackModules
                .findByUniqueProperties( [ 'initHighlighting', 'highlightBlock', 'highlightAuto' ] ),
        };

        /* Throw an error if a cached module can't be found. */
        for ( let prop in this.cachedModules ) {
            if ( typeof this.cachedModules[ prop ] !== 'object' ) {
                _alert( 'Error Loading DiscordCrypt', `Could not find requisite module: ${prop}` );
                return;
            }
        }

        /* Hook switch events as the main event processor. */
        if ( !this.hookMessageCallbacks() ) {
            /* The toolbar fails to properly load on switches to the friends list. Create an interval to do this. */
            this.toolbarReloadInterval = setInterval( () => {
                self.loadToolbar();
                self.attachHandler();
            }, 5000 );
        }
        else {
            setImmediate( () => {
                /* Add the toolbar. */
                this.loadToolbar();

                /* Attach the message handler. */
                this.attachHandler();
            } );
        }

        /* Setup Voice. */
        this.setupVoice();

        /* Process any blocks on an interval since Discord loves to throttle messages. */
        this.scanInterval = setInterval( () => {
            self.decodeMessages();
        }, self.configFile.encryptScanDelay );

        /* Setup the timed message handler to trigger every 5 seconds. */
        this.timedMessageInterval = setInterval( () => {
            /* Get the current time. */
            let n = Date.now();

            /* Loop over each message. */
            self.configFile.timedMessages.forEach( ( e, i ) => {
                /* Skip invalid elements. */
                if ( !e || !e.expireTime ) {
                    /* Delete the index. */
                    self.configFile.timedMessages.splice( i, 1 );

                    /* Update the configuration to the disk. */
                    self.saveConfig();
                }

                /* Only continue if the message has been expired. */
                if ( e.expireTime < n ) {
                    /* Quickly log. */
                    discordCrypt.log( `Deleting timed message "${self.configFile.timedMessages[ i ].messageId}"` );

                    try {
                        /* Delete the message. This will be queued if a rate limit is in effect. */
                        discordCrypt.deleteMessage( e.channelId, e.messageId, self.cachedModules );
                    }
                    catch ( e ) {
                        /* Log the error that occurred. */
                        discordCrypt.log( `${e.messageId}: ${e.toString()}`, 'error' );
                    }

                    /* Delete the index. */
                    self.configFile.timedMessages.splice( i, 1 );

                    /* Update the configuration to the disk. */
                    self.saveConfig();
                }
            } );

        }, 5000 );

        setImmediate( () => {
            /* Decode all messages immediately. */
            self.decodeMessages();
        } );
    }

    /**
     * @public
     * @desc Stops the script execution. This is called by BetterDiscord if the plugin is disabled or during shutdown.
     */
    stop() {
        /* Nothing needs to be done since start() wouldn't have triggered. */
        if ( !discordCrypt.validPluginName() )
            return;

        /* Remove onMessage event handler hook. */
        $( this.channelTextAreaClass ).off( "keydown.dcrypt" );

        /* Unhook switch events if available or fallback to clearing timed handlers. */
        if ( !this.unhookMessageCallbacks() ) {
            /* Unload the toolbar reload interval. */
            clearInterval( this.toolbarReloadInterval );
        }

        /* Unload the decryption interval. */
        clearInterval( this.scanInterval );

        /* Unload the timed message handler. */
        clearInterval( this.timedMessageInterval );

        /* Unload the update handler. */
        clearInterval( this.updateHandlerInterval );

        /* Unload elements. */
        $( "#dc-overlay" ).remove();
        $( '#dc-file-btn' ).remove();
        $( '#dc-lock-btn' ).remove();
        $( '#dc-passwd-btn' ).remove();
        $( '#dc-exchange-btn' ).remove();
        $( '#dc-settings-btn' ).remove();
        $( '#dc-quick-exchange-btn' ).remove();
        $( '#dc-clipboard-upload-btn' ).remove();

        /* Clear the configuration file. */
        this.configFile = null;
    }

    /**
     * @public
     * @desc Triggered when the script has to load resources. This is called once upon Discord startup.
     */
    load() {
        /* Inject application CSS. */
        discordCrypt.injectCSS( 'dc-css', discordCrypt.__zlibDecompress( this.appCss ) );

        /* Load necessary libraries. */
        discordCrypt.__loadLibraries( this.libraries );
    }

    /**
     * @public
     * @desc Triggered when the script needs to unload its resources. This is called during Discord shutdown.
     */
    unload() {
        /* Clear the injected CSS. */
        discordCrypt.clearCSS( 'dc-css' );
    }

    /* ========================================================= */

    /* ================= CONFIGURATION DATA CBS ================ */

    /**
     * @private
     * @desc Returns the default settings for the plugin.
     * @returns {Config}
     */
    getDefaultConfig() {
        return {
            /* Current Version. */
            version: this.getVersion(),
            /* Whether to send messages using embedded objects. */
            useEmbeds: false,
            /* Default password for servers not set. */
            defaultPassword: "⠓⣭⡫⣮⢹⢮⠖⣦⠬⢬⣸⠳⠜⣍⢫⠳⣂⠙⣵⡘⡕⠐⢫⢗⠙⡱⠁⡷⠺⡗⠟⠡⢴⢖⢃⡙⢺⣄⣑⣗⢬⡱⣴⠮⡃⢏⢚⢣⣾⢎⢩⣙⠁⣶⢁⠷⣎⠇⠦⢃⠦⠇⣩⡅",
            /* Defines what needs to be typed at the end of a message to encrypt it. */
            encodeMessageTrigger: "ENC",
            /* How often to scan for encrypted messages. */
            encryptScanDelay: 1000,
            /* Default encryption mode. */
            encryptMode: 7, /* AES(Camellia) */
            /* Default block operation mode for ciphers. */
            encryptBlockMode: 'CBC',
            /* Encode all messages automatically when a password has been set. */
            encodeAll: true,
            /* Default padding mode for blocks. */
            paddingMode: 'PKC7',
            /* Password array of objects for users or channels. */
            passList: {},
            /* Contains the URL of the Up1 client. */
            up1Host: 'https://share.riseup.net',
            /* Contains the API key used for transactions with the Up1 host. */
            up1ApiKey: '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
            /* Internal message list for time expiration. */
            timedMessages: [],
            /* How long after a message is sent to remove it. */
            timedMessageExpires: 0
        };
    }

    /**
     * @private
     * @desc Checks if the configuration file exists.
     * @returns {boolean} Returns true if the configuration file exists.
     */
    configExists() {
        /* Attempt to parse the configuration file. */
        let data = bdPluginStorage.get( this.getName(), 'config' );

        /* The returned data must be defined and non-empty. */
        return data && data !== null && data !== '';
    }

    /**
     * @private
     * @desc Loads the configuration file from `discordCrypt.config.json` and adds or removes any properties required.
     * @returns {boolean}
     */
    loadConfig() {
        discordCrypt.log( 'Loading configuration file ...' );

        /* Attempt to parse the configuration file. */
        let config = bdPluginStorage.get( this.getName(), 'config' );

        /* Check if the config file exists. */
        if ( !config || config === null || config === '' ) {
            /* File doesn't exist, create a new one. */
            this.configFile = this.getDefaultConfig();

            /* Save the config. */
            this.saveConfig();

            /* Nothing further to do. */
            return true;
        }

        try {
            /* Try parsing the decrypted data. */
            this.configFile = JSON.parse(
                discordCrypt.__zlibDecompress(
                    discordCrypt.aes256_decrypt_gcm( config.data, this.masterPassword, 'PKC7', 'base64', false ),
                    'base64',
                    'utf8'
                )
            );
        }
        catch ( err ) {
            discordCrypt.log( `Decryption of configuration file failed - ${err}`, 'error' );
            return false;
        }

        /* If it fails, return an error. */
        if ( !this.configFile || !this.configFile.version ) {
            discordCrypt.log( 'Decryption of configuration file failed.', 'error' );
            return false;
        }

        /* Try checking for each property within the config file and make sure it exists. */
        let defaultConfig = this.getDefaultConfig(), needs_save = false;

        /* Iterate all defined properties in the default configuration file. */
        for ( let prop in defaultConfig ) {
            /* If the defined property doesn't exist in the current configuration file ... */
            if ( !this.configFile.hasOwnProperty( prop ) ) {
                /* Use the default. */
                this.configFile[ prop ] = defaultConfig[ prop ];

                /* Show a simple log. */
                discordCrypt.log( `Default value added for missing property '${prop}' in the configuration file.` );

                /* Set the flag for saving. */
                needs_save = true;
            }
        }

        /* Iterate all defined properties in the current configuration file and remove any undefined ones. */
        for ( let prop in this.configFile ) {
            /* If the default configuration doesn't contain this property, delete it as it's unnecessary. */
            if ( !defaultConfig.hasOwnProperty( prop ) ) {
                /* Delete the property. */
                delete this.configFile[ prop ];

                /* Show a simple log. */
                discordCrypt.log( `Removing unknown property '${prop}' from the configuration file.` );

                /* Set the flag for saving. */
                needs_save = true;
            }
        }

        /* Check for version mismatch. */
        if ( this.configFile.version !== this.getVersion() ) {
            /* Preserve the old version for logging. */
            let oldVersion = this.configFile.version;

            /* Preserve the old password list before updating. */
            let oldCache = this.configFile.passList;

            /* Get the most recent default configuration. */
            this.configFile = this.getDefaultConfig();

            /* Now restore the password list. */
            this.configFile.passList = oldCache;

            /* Set the flag for saving. */
            needs_save = true;

            /* Alert. */
            discordCrypt.log( `Updated plugin version from v${oldVersion} to v${this.getVersion()}.` );
        }

        /* Save the configuration file if necessary. */
        if ( needs_save )
            this.saveConfig();

        discordCrypt.log( `Loaded configuration file! - v${this.configFile.version}` );

        return true;
    }

    /**
     * @private
     * @desc Saves the configuration file with the current password using AES-256 in GCM mode.
     */
    saveConfig() {
        /* Encrypt the message using the master password and save the encrypted data. */
        bdPluginStorage.set( this.getName(), 'config', {
            data:
                discordCrypt.aes256_encrypt_gcm(
                    discordCrypt.__zlibCompress(
                        JSON.stringify( this.configFile ),
                        'utf8'
                    ),
                    this.masterPassword,
                    'PKC7',
                    false
                )
        } );
    }

    /**
     * @private
     * @desc Updates and saves the configuration data used and updates a given button's text.
     * @param {Object} [btn] The jQuery button to set the update text for.
     */
    saveSettings( btn ) {
        /* Save the configuration file. */
        this.saveConfig();

        /* Force decode messages. */
        this.decodeMessages( true );

        if( btn ) {
            /* Tell the user that their settings were applied. */
            btn.text( 'Saved & Applied!' );

            /* Reset the original text after a second. */
            setTimeout( ( function () {
                btn.text( 'Save & Apply' );
            } ), 1000 );
        }
    }

    /**
     * @private
     * @desc Resets the default configuration data used and updates a given button's text.
     * @param {Object} [btn] The jQuery button to set the update text for.
     */
    resetSettings( btn ) {
        /* Preserve the old password list before resetting. */
        let oldCache = this.configFile.passList;

        /* Retrieve the default configuration. */
        this.configFile = this.getDefaultConfig();

        /* Restore the old passwords. */
        this.configFile.passList = oldCache;

        /* Save the configuration file to update any settings. */
        this.saveConfig();

        /* Force decode messages. */
        this.decodeMessages( true );

        if( btn ) {
            /* Tell the user that their settings were reset. */
            btn.text( 'Restored Default Settings!' );

            /* Reset the original text after a second. */
            setTimeout( ( function () {
                btn.text( 'Reset Settings' );
            } ), 1000 );
        }
    }

    /**
     * @private
     * @desc Update the current password field and save the config file.
     */
    updatePasswords() {
        /* Don't save if the password overlay is not open. */
        if ( $( '#dc-overlay-password' ).css( 'display' ) !== 'block' )
            return;

        let prim = $( "#dc-password-primary" );
        let sec = $( "#dc-password-secondary" );

        /* Check if a primary password has actually been entered. */
        if ( !( prim.val() !== '' && prim.val().length > 1 ) )
            delete this.configFile.passList[ discordCrypt.getChannelId() ];
        else {
            /* Update the password field for this id. */
            this.configFile.passList[ discordCrypt.getChannelId() ] =
                discordCrypt.createPassword( prim.val(), '' );

            /* Only check for a secondary password if the primary password has been entered. */
            if ( sec.val() !== '' && sec.val().length > 1 )
                this.configFile.passList[ discordCrypt.getChannelId() ].secondary = sec.val();

            /* Update the password toolbar. */
            prim.val( '' );
            sec.val( '' );
        }

        /* Save the configuration file and decode any messages. */
        this.saveConfig();

        /* Decode any messages with the new password(s). */
        this.decodeMessages( true );
    }

    /* ========================================================= */

    /* ==================== MAIN CALLBACKS ==================== */

    /**
     * @private
     * @desc Debug function that attempts to hook Discord's internal event handlers for message creation.
     * @return {boolean} Returns true if handler events have been hooked.
     */
    hookMessageCallbacks() {
        /* Find the main switch event dispatcher if not already found. */
        if ( !this.messageUpdateDispatcher ) {
            /* Usually ID_78. */
            this.messageUpdateDispatcher = discordCrypt.getWebpackModuleSearcher().findByDispatchNames( [
                'LOAD_MESSAGES',
                'LOAD_MESSAGES_SUCCESS',
                'LOAD_MESSAGES_FAILURE',
                'TRUNCATE_MESSAGES',
                'MESSAGE_CREATE',
                'MESSAGE_UPDATE',
                'MESSAGE_DELETE',
                'MESSAGE_DELETE_BULK',
                'MESSAGE_REVEAL',
                'CHANNEL_SELECT',
                'CHANNEL_CREATE',
                'CHANNEL_PRELOAD',
                'GUILD_CREATE',
                'GUILD_SELECT',
                'GUILD_DELETE'
            ] );
        }

        /* Don't proceed if it failed. */
        if ( !this.messageUpdateDispatcher ) {
            discordCrypt.log( `Failed to locate the switch event dispatcher!`, 'error' );
            return false;
        }

        /* Hook the switch event dispatcher. */
        discordCrypt.hookDispatcher(
            this.messageUpdateDispatcher,
            'CHANNEL_SELECT',
            {
                after: ( e ) => {
                    /* Skip channels not currently selected. */
                    if ( discordCrypt.getChannelId() !== e.methodArguments[ 0 ].channelId )
                        return;

                    /* Delays are required due to windows being loaded async. */
                    setTimeout(
                        () => {
                            discordCrypt.log( 'Detected chat switch.', 'debug' );

                            /* Add the toolbar. */
                            this.loadToolbar();

                            /* Attach the message handler. */
                            this.attachHandler();

                            /* Decrypt any messages. */
                            this.decodeMessages();
                        },
                        1
                    );
                }
            }
        );

        let messageUpdateEvent = {
            after: ( e ) => {
                /* Skip channels not currently selected. */
                if ( discordCrypt.getChannelId() !== e.methodArguments[ 0 ].channelId )
                    return;

                /* Delays are required due to windows being loaded async. */
                setTimeout(
                    () => {
                        /* Decrypt any messages. */
                        this.decodeMessages();
                    },
                    1
                );
            }
        };

        /* Hook incoming message creation dispatcher. */
        discordCrypt.hookDispatcher( this.messageUpdateDispatcher, 'MESSAGE_CREATE', messageUpdateEvent );
        discordCrypt.hookDispatcher( this.messageUpdateDispatcher, 'MESSAGE_UPDATE', messageUpdateEvent );
        discordCrypt.hookDispatcher( this.messageUpdateDispatcher, 'MESSAGE_DELETE', messageUpdateEvent );

        return true;
    }

    /**
     * @private
     * @desc Removes all hooks on modules hooked by the hookMessageCallbacks() function.
     * @return {boolean} Returns true if all methods have been unhooked.
     */
    unhookMessageCallbacks() {
        /* Skip if no dispatcher was called. */
        if ( !this.messageUpdateDispatcher )
            return false;

        /* Iterate over every dispatcher. */
        for ( let prop in this.messageUpdateDispatcher._actionHandlers ) {
            /* Search for the hooked property and call it. */
            if ( prop.hasOwnProperty( '__cancel' ) )
                prop.__cancel();
        }

        return true;
    }

    /**
     * @private
     * @desc Loads the master-password unlocking prompt.
     */
    loadMasterPassword() {
        const self = this;

        if ( $( '#dc-master-overlay' ).length !== 0 )
            return;

        /* Check if the database exists. */
        const cfg_exists = self.configExists();

        const action_msg = cfg_exists ? 'Unlock Database' : 'Create Database';

        /* Construct the password updating field. */
        $( document.body ).prepend( discordCrypt.__zlibDecompress( this.masterPasswordHtml ) );

        const pwd_field = $( '#dc-db-password' );
        const cancel_btn = $( '#dc-cancel-btn' );
        const unlock_btn = $( '#dc-unlock-database-btn' );
        const master_status = $( '#dc-master-status' );
        const master_header_message = $( '#dc-header-master-msg' );
        const master_prompt_message = $( '#dc-prompt-master-msg' );

        /* Use these messages based on whether we're creating a database or unlocking it. */
        master_header_message.text(
            cfg_exists ?
                '---------- Database Is Locked ----------' :
                '---------- Database Not Found ----------'
        );
        master_prompt_message.text(
            cfg_exists ?
                'Enter Password:' :
                'Enter New Password:'
        );
        unlock_btn.text( action_msg );

        /* Force the database element to load. */
        document.getElementById( 'dc-master-overlay' ).style.display = 'block';

        /* Check for ENTER key press to execute unlocks. */
        pwd_field.on( "keydown", ( function ( e ) {
            let code = e.keyCode || e.which;

            /* Execute on ENTER/RETURN only. */
            if ( code !== 13 )
                return;

            unlock_btn.click();
        } ) );

        /* Handle unlock button clicks. */
        unlock_btn.click(
            discordCrypt.on_master_unlock_button_clicked(
                self,
                unlock_btn,
                cfg_exists,
                pwd_field,
                action_msg,
                master_status
            )
        );

        /* Handle cancel button presses. */
        cancel_btn.click( discordCrypt.on_master_cancel_button_clicked( self ) );
    }

    /**
     * @private
     * @desc Performs an async update checking and handles actually updating the current version if necessary.
     */
    checkForUpdates() {
        const self = this;

        setTimeout( () => {
            /* Proxy call. */
            try {
                discordCrypt.checkForUpdate( ( file_data, short_hash, new_version, full_changelog, valid_sig ) => {
                    const replacePath = require( 'path' )
                        .join( discordCrypt.getPluginsPath(), discordCrypt.getPluginName() );
                    const fs = require( 'fs' );

                    /* Alert the user of the update and changelog. */
                    $( '#dc-overlay' ).css( 'display', 'block' );
                    $( '#dc-update-overlay' ).css( 'display', 'block' );

                    /* Update the version info. */
                    $( '#dc-new-version' )
                        .text( `New Version: ${new_version === '' ? 'N/A' : new_version} ( #${short_hash} )` );
                    $( '#dc-old-version' ).text(
                        `Current Version: ${self.getVersion()} ` +
                        `( Update ${valid_sig ? 'Verified' : 'Contains Invalid Signature. BE CAREFUL'}! )`
                    );

                    /* Update the changelog. */
                    let dc_changelog = $( '#dc-changelog' );
                    dc_changelog.val(
                        typeof full_changelog === "string" && full_changelog.length > 0 ?
                            discordCrypt.__tryParseChangelog( full_changelog, self.getVersion() ) :
                            'N/A'
                    );

                    /* Scroll to the top of the changelog. */
                    dc_changelog.scrollTop( 0 );

                    /* Replace the file. */
                    fs.writeFile( replacePath, file_data, ( err ) => {
                        if ( err ) {
                            discordCrypt.log(
                                `Unable to replace the target plugin. ( ${err} )\nDestination: ${replacePath}`, 'error'
                            );
                            _alert( 'Error During Update', 'Failed to apply the update!' );
                        }
                    } );
                } );
            }
            catch ( ex ) {
                discordCrypt.log( ex, 'warn' );
            }
        }, 1 );
    }

    /**
     * @private
     * @desc Inserts the plugin's option toolbar to the current toolbar and handles all triggers.
     */
    loadToolbar() {

        /* Skip if the configuration hasn't been loaded. */
        if ( !this.configFile )
            return;

        /* Skip if we're not in an active channel. */
        if ( discordCrypt.getChannelId() === '@me' )
            return;

        /* Add toolbar buttons and their icons if it doesn't exist. */
        if ( $( '#dc-passwd-btn' ).length !== 0 )
            return;

        /* Inject the toolbar. */
        $( this.searchUiClass ).parent().parent().parent().prepend( discordCrypt.__zlibDecompress( this.toolbarHtml ) );

        /* Cache jQuery results. */
        let dc_passwd_btn = $( '#dc-passwd-btn' ),
            dc_lock_btn = $( '#dc-lock-btn' ),
            dc_svg = $( '.dc-svg' );

        /* Set the SVG button class. */
        dc_svg.attr( 'class', 'dc-svg' );

        /* Set the initial status icon. */
        if ( dc_lock_btn.length > 0 ) {
            if ( this.configFile.encodeAll ) {
                dc_lock_btn.attr( 'title', 'Disable Message Encryption' );
                dc_lock_btn.html( Buffer.from( this.lockIcon, 'base64' ).toString( 'utf8' ) );
            }
            else {
                dc_lock_btn.attr( 'title', 'Enable Message Encryption' );
                dc_lock_btn.html( Buffer.from( this.unlockIcon, 'base64' ).toString( 'utf8' ) );
            }

            /* Set the button class. */
            dc_svg.attr( 'class', 'dc-svg' );
        }

        /* Inject the settings. */
        $( document.body ).prepend( discordCrypt.__zlibDecompress( this.settingsMenuHtml ) );

        /* Also by default, set the about tab to be shown. */
        discordCrypt.set_active_settings_tab( 0 );
        discordCrypt.set_active_exchange_tab( 0 );

        /* Update all settings from the settings panel. */
        $( '#dc-secondary-cipher' ).val( discordCrypt.cipherIndexToString( this.configFile.encryptMode, true ) );
        $( '#dc-primary-cipher' ).val( discordCrypt.cipherIndexToString( this.configFile.encryptMode, false ) );
        $( '#dc-settings-cipher-mode' ).val( this.configFile.encryptBlockMode.toLowerCase() );
        $( '#dc-settings-padding-mode' ).val( this.configFile.paddingMode.toLowerCase() );
        $( '#dc-settings-encrypt-trigger' ).val( this.configFile.encodeMessageTrigger );
        $( '#dc-settings-timed-expire' ).val( this.configFile.timedMessageExpires );
        $( '#dc-settings-default-pwd' ).val( this.configFile.defaultPassword );
        $( '#dc-settings-scan-delay' ).val( this.configFile.encryptScanDelay );
        $( '#dc-embed-enabled' ).prop( 'checked', this.configFile.useEmbeds );

        /* Handle clipboard upload button. */
        $( '#dc-clipboard-upload-btn' ).click( discordCrypt.on_upload_encrypted_clipboard_button_clicked( this ) );

        /* Handle file button clicked. */
        $( '#dc-file-btn' ).click( discordCrypt.on_file_button_clicked );

        /* Handle alter file path button. */
        $( '#dc-select-file-path-btn' ).click( discordCrypt.on_alter_file_button_clicked );

        /* Handle file upload button. */
        $( '#dc-file-upload-btn' ).click( discordCrypt.on_upload_file_button_clicked( this ) );

        /* Handle file button cancelled. */
        $( '#dc-file-cancel-btn' ).click( discordCrypt.on_cancel_file_upload_button_clicked );

        /* Handle Settings tab opening. */
        $( '#dc-settings-btn' ).click( discordCrypt.on_settings_button_clicked );

        /* Handle Plugin Settings tab selected. */
        $( '#dc-plugin-settings-btn' ).click( discordCrypt.on_plugin_settings_tab_button_clicked );

        /* Handle Database Settings tab selected. */
        $( '#dc-database-settings-btn' ).click( discordCrypt.on_database_settings_tab_button_clicked( this ) );

        /* Handle Database Import button. */
        $( '#dc-import-database-btn' ).click( discordCrypt.on_import_database_button_clicked( this ) );

        /* Handle Database Export button. */
        $( '#dc-export-database-btn' ).click( discordCrypt.on_export_database_button_clicked( this ) );

        /* Handle Clear Database Entries button. */
        $( '#dc-erase-entries-btn' ).click( discordCrypt.on_clear_entries_button_clicked( this ) );

        /* Handle Settings tab closing. */
        $( '#dc-exit-settings-btn' ).click( discordCrypt.on_settings_close_button_clicked );

        /* Handle Save settings. */
        $( '#dc-settings-save-btn' ).click( discordCrypt.on_save_settings_button_clicked( this ) );

        /* Handle Reset settings. */
        $( '#dc-settings-reset-btn' ).click( discordCrypt.on_reset_settings_button_clicked( this ) );

        /* Handle Restart-Now button clicking. */
        $( '#dc-restart-now-btn' ).click( discordCrypt.on_restart_now_button_clicked );

        /* Handle Restart-Later button clicking. */
        $( '#dc-restart-later-btn' ).click( discordCrypt.on_restart_later_button_clicked );

        /* Handle Info tab switch. */
        $( '#dc-tab-info-btn' ).click( discordCrypt.on_info_tab_button_clicked );

        /* Handle Keygen tab switch. */
        $( '#dc-tab-keygen-btn' ).click( discordCrypt.on_exchange_tab_button_clicked );

        /* Handle Handshake tab switch. */
        $( '#dc-tab-handshake-btn' ).click( discordCrypt.on_handshake_tab_button_clicked );

        /* Handle exit tab button. */
        $( '#dc-exit-exchange-btn' ).click( discordCrypt.on_close_exchange_button_clicked );

        /* Open exchange menu. */
        $( '#dc-exchange-btn' ).click( discordCrypt.on_open_exchange_button_clicked );

        /* Quickly generate and send a public key. */
        $( '#dc-quick-exchange-btn' ).click( discordCrypt.on_quick_send_public_key_button_clicked );

        /* Repopulate the bit length options for the generator when switching handshake algorithms. */
        $( '#dc-keygen-method' ).change( discordCrypt.on_exchange_algorithm_changed );

        /* Generate a new key-pair on clicking. */
        $( '#dc-keygen-gen-btn' ).click( discordCrypt.on_generate_new_key_pair_button_clicked );

        /* Clear the public & private key fields. */
        $( '#dc-keygen-clear-btn' ).click( discordCrypt.on_keygen_clear_button_clicked );

        /* Send the public key to the current channel. */
        $( '#dc-keygen-send-pub-btn' ).click( discordCrypt.on_keygen_send_public_key_button_clicked( this ) );

        /* Paste the data from the clipboard to the public key field. */
        $( '#dc-handshake-paste-btn' ).click( discordCrypt.on_handshake_paste_public_key_button_clicked );

        /* Compute the primary and secondary keys. */
        $( '#dc-handshake-compute-btn' ).click( discordCrypt.on_handshake_compute_button_clicked( this ) );

        /* Copy the primary and secondary key to the clipboard. */
        $( '#dc-handshake-cpy-keys-btn' ).click( discordCrypt.on_handshake_copy_keys_button_clicked );

        /* Apply generated keys to the current channel. */
        $( '#dc-handshake-apply-keys-btn' ).click( discordCrypt.on_handshake_apply_keys_button_clicked( this ) );

        /* Show the overlay when clicking the password button. */
        dc_passwd_btn.click( discordCrypt.on_passwd_button_clicked );

        /* Update the password for the user once clicked. */
        $( '#dc-save-pwd' ).click( discordCrypt.on_save_passwords_button_clicked( this ) );

        /* Reset the password for the user to the default. */
        $( '#dc-reset-pwd' ).click( discordCrypt.on_reset_passwords_button_clicked( this ) );

        /* Hide the overlay when clicking cancel. */
        $( '#dc-cancel-btn' ).click( discordCrypt.on_cancel_password_button_clicked );

        /* Copy the current passwords to the clipboard. */
        $( '#dc-cpy-pwds-btn' ).click( discordCrypt.on_copy_current_passwords_button_clicked( this ) );

        /* Set whether auto-encryption is enabled or disabled. */
        dc_lock_btn.click( discordCrypt.on_lock_button_clicked( this ) );
    }

    /**
     * @private
     * @desc Attached a handler to the message area and dispatches encrypted messages if necessary.
     */
    attachHandler() {
        const self = this;

        /* Get the text area. */
        let textarea = $( this.channelTextAreaClass );

        /* Make sure we got one element. */
        if ( textarea.length !== 1 )
            return;

        /* Replace any old handlers before adding the new one. */
        textarea.off( "keydown.dcrypt" ).on( "keydown.dcrypt", ( function ( e ) {
            let code = e.keyCode || e.which;

            /* Skip if we don't have a valid configuration. */
            if ( !self.configFile )
                return;

            /* Execute on ENTER/RETURN only. */
            if ( code !== 13 )
                return;

            /* Skip if shift key is down indicating going to a new line. */
            if ( e.shiftKey )
                return;

            /* Skip if autocomplete dialog is opened. */
            if ( $( self.autoCompleteClass )[ 0 ] )
                return;

            /* Send the encrypted message. */
            if ( !self.sendEncryptedMessage( $( this ).val() ) )
                return;

            /* Clear text field. */
            discordCrypt.__getElementReactOwner( $( 'form' )[ 0 ] ).setState( { textValue: '' } );

            /* Cancel the default sending action. */
            e.preventDefault();
            e.stopPropagation();
        } ) );
    }

    /**
     * @private
     * @desc Parses a public key message and adds the exchange button to it if necessary.
     * @param {Object} obj The jQuery object of the current message being examined.
     * @returns {boolean} Returns true.
     */
    parseKeyMessage( obj ) {
        /* Extract the algorithm info from the message's metadata. */
        let metadata = discordCrypt.__extractKeyInfo( obj.text().replace( /\r?\n|\r/g, '' ), true );

        /* Sanity check for invalid key messages. */
        if ( metadata === null )
            return true;

        /* Compute the fingerprint of our currently known public key if any to determine if to proceed. */
        let local_fingerprint = discordCrypt.sha256( Buffer.from( $( '#dc-pub-key-ta' ).val(), 'hex' ), 'hex' );

        /* Skip if this is our current public key. */
        if ( metadata[ 'fingerprint' ] === local_fingerprint ) {
            obj.css( 'display', 'none' );
            return true;
        }

        /* Create a button allowing the user to perform a key exchange with this public key. */
        let button = $( "<button>Perform Key Exchange</button>" )
            .addClass( 'dc-button' )
            .addClass( 'dc-button-inverse' );

        /* Remove margins. */
        button.css( 'margin-left', '0' );
        button.css( 'margin-right', '0' );

        /* Move the button a bit down from the key's text. */
        button.css( 'margin-top', '2%' );

        /* Allow full width. */
        button.css( 'width', '100%' );

        /* Handle clicks. */
        button.click( ( function () {

            /* Cache jQuery results. */
            let dc_keygen_method = $( '#dc-keygen-method' ),
                dc_keygen_algorithm = $( '#dc-keygen-algorithm' );

            /* Simulate pressing the exchange key button. */
            $( '#dc-exchange-btn' ).click();

            /* If the current algorithm differs, change it and generate then send a new key. */
            if (
                dc_keygen_method.val() !== metadata[ 'algorithm' ] ||
                parseInt( dc_keygen_algorithm.val() ) !== metadata[ 'bit_length' ]
            ) {
                /* Switch. */
                dc_keygen_method.val( metadata[ 'algorithm' ] );

                /* Fire the change event so the second list updates. */
                dc_keygen_method.change();

                /* Update the key size. */
                dc_keygen_algorithm.val( metadata[ 'bit_length' ] );

                /* Generate a new key pair. */
                $( '#dc-keygen-gen-btn' ).click();

                /* Send the public key. */
                $( '#dc-keygen-send-pub-btn' ).click();
            }
            /* If we don't have a key yet, generate and send one. */
            else if ( $( '#dc-pub-key-ta' ).val() === '' ) {
                /* Generate a new key pair. */
                $( '#dc-keygen-gen-btn' ).click();

                /* Send the public key. */
                $( '#dc-keygen-send-pub-btn' ).click();
            }

            /* Open the handshake menu. */
            $( '#dc-tab-handshake-btn' ).click();

            /* Apply the key to the field. */
            $( '#dc-handshake-ppk' ).val( obj.text() );

            /* Click compute. */
            $( '#dc-handshake-compute-btn' ).click();
        } ) );

        /* Add the button. */
        obj.parent().append( button );

        /* Set the text to an identifiable color. */
        obj.css( 'color', 'blue' );

        return true;
    }

    /**
     * @private
     * @desc Parses a message object and attempts to decrypt it..
     * @param {Object} obj The jQuery object of the current message being examined.
     * @param {string} primary_key The primary key used to decrypt the message.
     * @param {string} secondary_key The secondary key used to decrypt the message.
     * @param {boolean} as_embed Whether to consider this message object as an embed.
     * @param {ReactModules} react_modules The modules retrieved by calling getReactModules()
     * @returns {boolean} Returns true if the message has been decrypted.
     */
    parseSymmetric( obj, primary_key, secondary_key, as_embed, react_modules ) {
        let message = $( obj );
        let dataMsg;

        /**************************************************************************************************************
         *  MESSAGE FORMAT:
         *
         *  + 0x0000 [ 4        Chars ] - Message Magic | Key Magic
         *  + 0x0004 [ 4 ( #4 ) Chars ] - Message Metadata ( #1 ) | Key Data ( #3 )
         *  + 0x000C [ ?        Chars ] - Cipher Text
         *
         *  * 0x0004 - Options - Substituted Base64 encoding of a single word stored in Little Endian.
         *      [ 31 ... 24 ] - Algorithm ( 0-24 = Dual )
         *      [ 23 ... 16 ] - Block Mode ( 0 = CBC | 1 = CFB | 2 = OFB )
         *      [ 15 ... 08 ] - Padding Mode ( #2 )
         *      [ 07 ... 00 ] - Random Padding Byte
         *
         *  #1 - Substitute( Base64( Encryption Algorithm << 24 | Padding Mode << 16 | Block Mode << 8 | RandomByte ) )
         *  #2 - ( 0 - PKCS #7 | 1 = ANSI X9.23 | 2 = ISO 10126 | 3 = ISO97971 )
         *  #3 - Substitute( Base64( ( Key Algorithm Type & 0xff ) + Public Key ) )
         *  #4 - 8 Byte Metadata For Messages Only
         *
         **************************************************************************************************************/

        /* Skip if the message is <= size of the total header. */
        if ( message.text().length <= 12 )
            return false;

        /* Split off the magic. */
        let magic = message.text().slice( 0, 4 );

        /* If this is a public key, just add a button and continue. */
        if ( magic === this.encodedKeyHeader )
            return this.parseKeyMessage( message );

        /* Make sure it has the correct header. */
        if ( magic !== this.encodedMessageHeader )
            return false;

        /* Try to deserialize the metadata. */
        let metadata = discordCrypt.metaDataDecode( message.text().slice( 4, 8 ) );

        /* Try looking for an algorithm, mode and padding type. */
        /* Algorithm first. */
        if ( metadata[ 0 ] >= this.encryptModes.length )
            return false;

        /* Cipher mode next. */
        if ( metadata[ 1 ] >= this.encryptBlockModes.length )
            return false;

        /* Padding after. */
        if ( metadata[ 2 ] >= this.paddingModes.length )
            return false;

        /* Decrypt the message. */
        dataMsg = discordCrypt.symmetricDecrypt( message.text().replace( /\r?\n|\r/g, '' )
            .substr( 8 ), primary_key, secondary_key, metadata[ 0 ], metadata[ 1 ], metadata[ 2 ], true );

        /* If decryption didn't fail, set the decoded text along with a green foreground. */
        if ( ( typeof dataMsg === 'string' || dataMsg instanceof String ) && dataMsg !== "" ) {
            /* If this is an embed, increase the maximum width of it. */
            if ( as_embed ) {
                /* Expand the message to the maximum width. */
                message.parent().parent().parent().parent().css( 'max-width', '100%' );
            }

            /* Process the message and apply all necessary element modifications. */
            dataMsg = this.postProcessMessage( dataMsg, this.configFile.up1Host );

            /* Handle embeds and inline blocks differently. */
            if ( as_embed ) {
                /* Set the new HTML. */
                message.html( dataMsg.html );
            }
            else {
                /* For inline code blocks, we set the HTML to the parent element. */
                let tmp = message.parent();
                message.parent().html( dataMsg.html );

                /* And update the message object with the parent element. */
                message = $( tmp );
            }

            /* If this contains code blocks, highlight them. */
            if ( dataMsg.code ) {
                /* Sanity check. */
                if ( react_modules.HighlightJS !== null ) {
                    /* The inner element contains a <span></span> class, get all children beneath that. */
                    let elements = $( message.children()[ 0 ] ).children();

                    /* Loop over each element to get the markup division list. */
                    for ( let i = 0; i < elements.length; i++ ) {
                        /* Highlight the element's <pre><code></code></code> block. */
                        react_modules.HighlightJS.highlightBlock( $( elements[ i ] ).children()[ 0 ] );

                        /* Reset the class name. */
                        $( elements[ i ] ).children().addClass( 'hljs' );
                    }
                }
                else
                    discordCrypt.log( 'Could not locate HighlightJS module!', 'error' );
            }

            /* Decrypted messages get set to green. */
            message.css( 'color', 'green' );
        }
        else {
            /* If it failed, set a red foreground and set a decryption failure message to prevent further retries. */
            if ( dataMsg === 1 )
                message.text( '[ ERROR ] AUTHENTICATION OF CIPHER TEXT FAILED !!!' );
            else if ( dataMsg === 2 )
                message.text( '[ ERROR ] FAILED TO DECRYPT CIPHER TEXT !!!' );
            else
                message.text( '[ ERROR ] DECRYPTION FAILURE. INVALID KEY OR MALFORMED MESSAGE !!!' );
            message.css( 'color', 'red' );
        }

        /* Message has been parsed. */
        return true;
    }

    /**
     * @private
     * @desc Processes a decrypted message and formats any elements needed in HTML.
     * @param message The message to process.
     * @param {string} [embed_link_prefix] Optional search link prefix for URLs to embed in frames.
     * @returns {ProcessedMessage}
     */
    postProcessMessage( message, embed_link_prefix ) {
        /* HTML escape characters. */
        const html_escape_characters = { '&': '&amp;', '<': '&lt', '>': '&gt;' };

        /* Remove any injected HTML. */
        message = message.replace( /[&<>]/g, x => html_escape_characters[ x ] );

        /* Extract any code blocks from the message. */
        let processed = discordCrypt.__buildCodeBlockMessage( message );
        let hasCode = processed.code;

        /* Extract any URLs. */
        processed = discordCrypt.__buildUrlMessage( processed.html, embed_link_prefix );
        let hasUrl = processed.url;

        /* Return the raw HTML. */
        return {
            url: hasUrl,
            code: hasCode,
            html: processed.html,
        };
    }

    /**
     * @private
     * @desc Iterates all messages in the current channel and tries to decrypt each, skipping cached results.
     */
    decodeMessages() {
        /* Skip if a valid configuration file has not been loaded. */
        if ( !this.configFile || !this.configFile.version )
            return;

        /* Save self. */
        const self = this;

        /* Get the current channel ID. */
        let id = discordCrypt.getChannelId();

        /* Use the default password for decryption if one hasn't been defined for this channel. */
        let primary = Buffer.from(
            this.configFile.passList[ id ] && this.configFile.passList[ id ].primary ?
                this.configFile.passList[ id ].primary :
                this.configFile.defaultPassword
        );
        let secondary = Buffer.from(
            this.configFile.passList[ id ] && this.configFile.passList[ id ].secondary ?
                this.configFile.passList[ id ].secondary :
                this.configFile.defaultPassword
        );

        /* Look through each markup element to find an embedDescription. */
        let React = discordCrypt.getReactModules( this.cachedModules );
        $( this.messageMarkupClass ).each( ( function () {
            /* Skip classes with no embeds. */
            if ( !this.className.includes( 'embedDescription' ) )
                return;

            /* Skip parsed messages. */
            if ( $( this ).data( 'dc-parsed' ) !== undefined )
                return;

            /* Try parsing a symmetric message. */
            self.parseSymmetric( this, primary, secondary, true, React );

            /* Set the flag. */
            $( this ).data( 'dc-parsed', true );
        } ) );

        /* Look through markup classes for inline code blocks. */
        $( `${this.messageMarkupClass} .inline` ).each( ( function () {
            /* Skip parsed messages. */
            if ( $( this ).data( 'dc-parsed' ) !== undefined )
                return;

            /* Try parsing a symmetric message. */
            self.parseSymmetric( this, primary, secondary, false, React );

            /* Set the flag. */
            $( this ).data( 'dc-parsed', true );
        } ) );
    }

    /**
     * @private
     * @desc Sends an encrypted message to the current channel.
     * @param {string} message The unencrypted message to send.
     * @param {boolean} [force_send] Whether to ignore checking for the encryption trigger and always encrypt and send.
     * @param {int} [channel_id] If specified, sends the embedded message to this channel instead of the current
     *      channel.
     * @returns {boolean} Returns false if the message failed to be parsed correctly and 0 on success.
     */
    sendEncryptedMessage( message, force_send = false, channel_id = undefined ) {
        /* Let's use a maximum message size of 1820 instead of 2000 to account for encoding, new line feeds & packet
         header. */
        const maximum_encoded_data = 1820;

        /* Add the message signal handler. */
        const escapeCharacters = [ "#", "/", ":" ];
        const crypto = require( 'crypto' );

        let cleaned;

        /* Skip messages starting with pre-defined escape characters. */
        if ( escapeCharacters.indexOf( message[ 0 ] ) !== -1 )
            return false;

        /* If we're not encoding all messages or we don't have a password, strip off the magic string. */
        if ( force_send === false &&
            ( !this.configFile.passList[ discordCrypt.getChannelId() ] ||
                !this.configFile.passList[ discordCrypt.getChannelId() ].primary ||
                !this.configFile.encodeAll )
        ) {
            /* Try splitting via the defined split-arg. */
            message = message.split( '|' );

            /* Check if the message actually has the split arg. */
            if ( message.length <= 0 )
                return false;

            /* Check if it has the trigger. */
            if ( message[ message.length - 1 ] !== this.configFile.encodeMessageTrigger )
                return false;

            /* Use the first part of the message. */
            cleaned = message[ 0 ];
        }
        /* Make sure we have a valid password. */
        else {
            /* Use the whole message. */
            cleaned = message;
        }

        /* Check if we actually have a message ... */
        if ( cleaned.length === 0 )
            return false;

        /* Try parsing any user-tags. */
        let parsed = discordCrypt.__extractTags( cleaned );

        /* Sanity check for messages with just spaces or new line feeds in it. */
        if ( parsed[ 0 ].length !== 0 ) {
            /* Extract the message to be encrypted. */
            cleaned = parsed[ 0 ];
        }

        /* Add content tags. */
        let user_tags = parsed[ 1 ].length > 0 ? parsed[ 1 ] : '';

        /* Get the passwords. */
        let primaryPassword = Buffer.from(
            this.configFile.passList[ discordCrypt.getChannelId() ] ?
                this.configFile.passList[ discordCrypt.getChannelId() ].primary :
                this.configFile.defaultPassword
        );

        let secondaryPassword = Buffer.from(
            this.configFile.passList[ discordCrypt.getChannelId() ] ?
                this.configFile.passList[ discordCrypt.getChannelId() ].secondary :
                this.configFile.defaultPassword
        );

        /* If the message length is less than the threshold, we can send it without splitting. */
        if ( ( cleaned.length + 16 ) < maximum_encoded_data ) {
            /* Encrypt the message. */
            let msg = discordCrypt.symmetricEncrypt(
                cleaned,
                primaryPassword,
                secondaryPassword,
                this.configFile.encryptMode,
                this.configFile.encryptBlockMode,
                this.configFile.paddingMode,
                true
            );

            /* Append the header to the message normally. */
            msg = this.encodedMessageHeader + discordCrypt.metaDataEncode
            (
                this.configFile.encryptMode,
                this.configFile.encryptBlockMode,
                this.configFile.paddingMode,
                parseInt( crypto.pseudoRandomBytes( 1 )[ 0 ] )
            ) + msg;

            /* Break up the message into lines. */
            msg = msg.replace( /(.{32})/g, ( e ) => {
                return `${e}\n`
            } );

            /* Send the message. */
            discordCrypt.dispatchMessage(
                this.configFile.useEmbeds,
                msg,
                this.messageHeader,
                `v${this.getVersion().replace( '-debug', '' )}`,
                0x551A8B,
                user_tags,
                channel_id,
                this.cachedModules,
                this.configFile.timedMessages,
                this.configFile.timedMessageExpires
            );
        }
        else {
            /* Determine how many packets we need to split this into. */
            let packets = discordCrypt.__splitStringChunks( cleaned, maximum_encoded_data );
            for ( let i = 0; i < packets.length; i++ ) {
                /* Encrypt the message. */
                let msg = discordCrypt.symmetricEncrypt(
                    packets[ i ],
                    primaryPassword,
                    secondaryPassword,
                    this.configFile.encryptMode,
                    this.configFile.encryptBlockMode,
                    this.configFile.paddingMode,
                    true
                );

                /* Append the header to the message normally. */
                msg = this.encodedMessageHeader + discordCrypt.metaDataEncode
                (
                    this.configFile.encryptMode,
                    this.configFile.encryptBlockMode,
                    this.configFile.paddingMode,
                    parseInt( crypto.pseudoRandomBytes( 1 )[ 0 ] )
                ) + msg;

                /* Break up the message into lines. */
                msg = msg.replace( /(.{32})/g, ( e ) => {
                    return `${e}\n`
                } );

                /* Send the message. */
                discordCrypt.dispatchMessage(
                    this.configFile.useEmbeds,
                    msg,
                    this.messageHeader,
                    `v${this.getVersion().replace( '-debug', '' )}`,
                    0x551A8B,
                    i === 0 ? user_tags : '',
                    channel_id,
                    this.cachedModules,
                    this.configFile.timedMessages,
                    this.configFile.timedMessageExpires
                );
            }
        }

        /* Save the configuration file and store the new message(s). */
        this.saveConfig();

        return true;
    }

    /**
     * @private
     * @desc Sets up the plugin's voice hooks.
     */
    setupVoice() {
        /**
         * @protected
         * @desc Patches a specific prototype with the new function.
         * @param {Array<string>|string} name The name or names of prototypes to search for.
         *      The first name will be patched if this is an array.
         * @param {function} fn The function to override the call with.
         * @param scanner
         */
        const patchPrototype = ( name, fn, scanner ) => {
            try {
                if( Array.isArray( name ) )
                    scanner( name ).prototype[ name[ 0 ] ] = fn;
                else
                    scanner( [ name ] ).prototype[ name ] = fn;
            }
            catch( e ) {
                discordCrypt.log(
                    `Failed to patch prototype: ${Array.isArray( name ) ? name[ 0 ] : name}\n${e}`,
                    'error'
                );
            }
        };

        /* Retrieve the scanner. */
        let searcher = discordCrypt.getWebpackModuleSearcher();

        /* Remove quality reports. */
        patchPrototype(
            '_sendQualityReports',
            () => {
                discordCrypt.log( 'Blocking voice quality report.', 'info' );
            },
            searcher.findByUniquePrototypes
        );
    }

    /* ========================================================= */

    /* ================== UI HANDLE CALLBACKS ================== */

    /**
     * @desc Attempts to unlock the database upon startup.
     * @param {discordCrypt} self
     * @param {Object} unlock_btn
     * @param {boolean} cfg_exists
     * @param {Object} pwd_field
     * @param {string} action_msg
     * @param {Object} master_status
     * @return {Function}
     */
    static on_master_unlock_button_clicked( self, unlock_btn, cfg_exists, pwd_field, action_msg, master_status ) {
        return () => {
            /* Disable the button before clicking. */
            unlock_btn.attr( 'disabled', true );

            /* Update the text. */
            if ( cfg_exists )
                unlock_btn.text( 'Unlocking Database ...' );
            else
                unlock_btn.text( 'Creating Database ...' );

            /* Get the password entered. */
            let password = pwd_field.val();

            /* Validate the field entered contains some value. */
            if ( password === null || password === '' ) {
                unlock_btn.text( action_msg );
                unlock_btn.attr( 'disabled', false );
                return;
            }

            /* Hash the password. */
            discordCrypt.scrypt
            (
                Buffer.from( password ),
                Buffer.from( discordCrypt.whirlpool( password, true ), 'hex' ),
                32,
                4096,
                8,
                1,
                ( error, progress, pwd ) => {
                    if ( error ) {
                        /* Update the button's text. */
                        if ( cfg_exists )
                            unlock_btn.text( 'Invalid Password!' );
                        else
                            unlock_btn.text( `Error: ${error}` );

                        /* Clear the text field. */
                        pwd_field.val( '' );

                        /* Reset the progress bar. */
                        master_status.css( 'width', '0%' );

                        /* Reset the text of the button after 1 second. */
                        setTimeout( ( function () {
                            unlock_btn.text( action_msg );
                        } ), 1000 );

                        discordCrypt.log( error.toString(), 'error' );
                        return true;
                    }

                    if ( progress )
                        master_status.css( 'width', `${parseInt( progress * 100 )}%` );

                    if ( pwd ) {
                        /* To test whether this is the correct password or not, we have to attempt to use it. */
                        self.masterPassword = Buffer.from( pwd, 'hex' );

                        /* Attempt to load the database with this password. */
                        if ( !self.loadConfig() ) {
                            self.configFile = null;

                            /* Update the button's text. */
                            if ( cfg_exists )
                                unlock_btn.text( 'Invalid Password!' );
                            else
                                unlock_btn.text( 'Failed to create the database!' );

                            /* Clear the text field. */
                            pwd_field.val( '' );

                            /* Reset the progress bar. */
                            master_status.css( 'width', '0%' );

                            /* Reset the text of the button after 1 second. */
                            setTimeout( ( function () {
                                unlock_btn.text( action_msg );
                            } ), 1000 );

                            /* Proceed no further. */
                            unlock_btn.attr( 'disabled', false );
                            return false;
                        }

                        /* We may now call the start() function. */
                        self.start();

                        /* And update the button text. */
                        if ( cfg_exists )
                            unlock_btn.text( 'Unlocked Successfully!' );
                        else
                            unlock_btn.text( 'Created Successfully!' );

                        /* Close the overlay after 1 second. */
                        setTimeout( ( function () {
                            $( '#dc-master-overlay' ).remove();
                        } ), 1000 );
                    }

                    return false;
                }
            );
        }
    }

    /**
     * @desc Cancels loading the plugin when the unlocking cancel button is pressed.
     * @param {discordCrypt} self
     * @return {Function}
     */
    static on_master_cancel_button_clicked( self ) {
        return () => {
            /* Use a 300 millisecond delay. */
            setTimeout(
                ( function () {
                    /* Remove the prompt overlay. */
                    $( '#dc-master-overlay' ).remove();

                    /* Do some quick cleanup. */
                    self.masterPassword = null;
                    self.configFile = null;
                } ), 300
            );
        }
    }

    /**
     * @private
     * @desc Opens the file uploading menu.
     */
    static on_file_button_clicked() {
        /* Show main background. */
        $( '#dc-overlay' ).css( 'display', 'block' );

        /* Show the upload overlay. */
        $( '#dc-overlay-upload' ).css( 'display', 'block' );
    }

    /**
     * @private
     * @desc Opens the file menu selection.
     */
    static on_alter_file_button_clicked() {
        /* Create an input element. */
        let file = require( 'electron' ).remote.dialog.showOpenDialog( {
            title: 'Select a file to encrypt and upload',
            buttonLabel: 'Select',
            message: 'Maximum file size is 50 MB',
            properties: [ 'openFile', 'showHiddenFiles', 'treatPackageAsDirectory' ]
        } );

        /* Ignore if no file was selected. */
        if ( !file.length || !file[ 0 ].length )
            return;

        /* Set the file path to the selected path. */
        $( '#dc-file-path' ).val( file[ 0 ] );
    }

    /**
     * @private
     * @desc Uploads the clipboard's current contents and sends the encrypted link.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_upload_encrypted_clipboard_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Since this is an async operation, we need to backup the channel ID before doing this. */
            let channel_id = discordCrypt.getChannelId();

            /* Upload the clipboard. */
            discordCrypt.__up1UploadClipboard(
                self.configFile.up1Host,
                self.configFile.up1ApiKey,
                global.sjcl,
                ( error_string, file_url, deletion_link ) => {
                    /* Do some sanity checking. */
                    if ( error_string !== null || typeof file_url !== 'string' || typeof deletion_link !== 'string' ) {
                        _alert( 'Failed to upload the clipboard!', error_string );
                        return;
                    }

                    /* Format and send the message. */
                    self.sendEncryptedMessage( `${file_url}`, true, channel_id );

                    /* Copy the deletion link to the clipboard. */
                    require( 'electron' ).clipboard.writeText( `Delete URL: ${deletion_link}` );
                }
            );
        };
    }

    /**
     * @private
     * @desc  Uploads the selected file and sends the encrypted link.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_upload_file_button_clicked( /* discordCrypt */ self ) {
        return () => {
            const fs = require( 'original-fs' );

            let file_path_field = $( '#dc-file-path' );
            let file_upload_btn = $( '#dc-file-upload-btn' );
            let message_textarea = $( '#dc-file-message-textarea' );
            let send_deletion_link = $( '#dc-file-deletion-checkbox' ).is( ':checked' );
            let randomize_file_name = $( '#dc-file-name-random-checkbox' ).is( ':checked' );

            /* Send the additional text first if it's valid. */
            if ( message_textarea.val().length > 0 )
                self.sendEncryptedMessage( message_textarea.val(), true );

            /* Since this is an async operation, we need to backup the channel ID before doing this. */
            let channel_id = discordCrypt.getChannelId();

            /* Clear the message field. */
            message_textarea.val( '' );

            /* Sanity check the file. */
            if ( !fs.existsSync( file_path_field.val() ) ) {
                file_path_field.val( '' );
                return;
            }

            /* Set the status text. */
            file_upload_btn.text( 'Uploading ...' );
            file_upload_btn.addClass( 'dc-button-inverse' );

            /* Upload the file. */
            discordCrypt.__up1UploadFile(
                file_path_field.val(),
                self.configFile.up1Host,
                self.configFile.up1ApiKey,
                global.sjcl,
                ( error_string, file_url, deletion_link ) => {
                    /* Do some sanity checking. */
                    if ( error_string !== null || typeof file_url !== 'string' || typeof deletion_link !== 'string' ) {
                        /* Set the status text. */
                        file_upload_btn.text( 'Failed to upload the file!' );
                        discordCrypt.log( error_string, 'error' );

                        /* Clear the file path. */
                        file_path_field.val( '' );

                        /* Reset the status text after 1 second. */
                        setTimeout( () => {
                            file_upload_btn.text( 'Upload' );
                            file_upload_btn.removeClass( 'dc-button-inverse' );
                        }, 1000 );

                        return;
                    }

                    /* Format and send the message. */
                    self.sendEncryptedMessage(
                        `${file_url}${send_deletion_link ? '\n\nDelete URL: ' + deletion_link : ''}`,
                        true,
                        channel_id
                    );

                    /* Clear the file path. */
                    file_path_field.val( '' );

                    /* Indicate success. */
                    file_upload_btn.text( 'Upload Successful!' );

                    /* Reset the status text after 1 second and close the dialog. */
                    setTimeout( () => {
                        file_upload_btn.text( 'Upload' );
                        file_upload_btn.removeClass( 'dc-button-inverse' );

                        /* Close. */
                        $( '#dc-file-cancel-btn' ).click();
                    }, 1000 );
                },
                randomize_file_name
            );
        };
    }

    /**
     * @private
     * @desc Closes the file upload dialog.
     */
    static on_cancel_file_upload_button_clicked() {
        /* Clear old file name. */
        $( '#dc-file-path' ).val( '' );

        /* Show main background. */
        $( '#dc-overlay' ).css( 'display', 'none' );

        /* Show the upload overlay. */
        $( '#dc-overlay-upload' ).css( 'display', 'none' );
    }

    /**
     * @private
     * @desc Opens the settings menu.
     */
    static on_settings_button_clicked() {
        /* Show main background. */
        $( '#dc-overlay' ).css( 'display', 'block' );

        /* Show the main settings menu. */
        $( '#dc-overlay-settings' ).css( 'display', 'block' );
    }

    /**
     * @private
     * @desc Selects the Plugin Settings tab.
     */
    static on_plugin_settings_tab_button_clicked() {
        /* Select the plugin settings. */
        discordCrypt.set_active_settings_tab( 0 );
    }

    /**
     * @private
     * @desc Selects the Database Settings tab and loads key info.
     * @param {discordCrypt} self
     * @return {Function}
     */
    static on_database_settings_tab_button_clicked( self ) {
        return () => {
            let users, guilds, channels, table;

            /* Cache the table. */
            table = $( '#dc-database-entries' );

            /* Clear all entries. */
            table.html( '' );

            /* Resolve all users, guilds and channels the current user is a part of. */
            users = self.cachedModules.UserResolver.getUsers();
            guilds = self.cachedModules.GuildResolver.getGuilds();
            channels = self.cachedModules.ChannelResolver.getChannels();

            /* Iterate over each password in the configuration. */
            for ( let prop in self.configFile.passList ) {
                let name, id = prop;

                /* Skip channels that don't have an ID. */
                if ( !channels[ id ] )
                    continue;

                /* Check for the correct channel type. */
                if ( channels[ id ].type === 0 ) {
                    /* Guild Channel */
                    let guild = guilds[ channels[ id ].guild_id ];

                    /* Resolve the name as a "Guild @ #Channel" format. */
                    name = `${guild.name} @ #${channels[ id ].name}`;
                }
                else if ( channels[ id ].type === 1 ) {
                    /* DM */
                    let user = users[ channels[ id ].recipients[ 0 ] ];

                    /* Indicate this is a DM and give the full user name. */
                    name = `DM @${user.username}#${user.discriminator}`;
                }
                else
                    continue;

                /* Create the elements needed for building the row. */
                let element =
                        $( `<tr><td>${id}</td><td>${name}</td><td><div style="display:flex;"></div></td></tr>` ),
                    delete_btn = $( '<button>' )
                        .addClass( 'dc-button dc-button-small dc-button-inverse' )
                        .text( 'Delete' ),
                    copy_btn = $( '<button>' )
                        .addClass( 'dc-button dc-button-small dc-button-inverse' )
                        .text( 'Copy' );

                /* Handle deletion clicks. */
                delete_btn.click( function () {
                    /* Delete the entry. */
                    delete self.configFile.passList[ id ];

                    /* Save the configuration. */
                    self.saveConfig();

                    /* Remove the entire row. */
                    delete_btn.parent().parent().remove();
                } );

                /* Handle copy clicks. */
                copy_btn.click( function() {
                    /* Resolve the entry. */
                    let current_keys = self.configFile.passList[ id ];

                    /* Write to the clipboard. */
                    require( 'electron' ).clipboard.writeText(
                        `Primary Key: ${current_keys.primary}\n\nSecondary Key: ${current_keys.secondary}`
                    );

                    copy_btn.text( 'Copied' );

                    setTimeout( () => {
                        copy_btn.text( 'Copy' );
                    }, 1000 );
                } );

                /* Append the button to the Options column. */
                $( $( element.children()[ 2 ] ).children()[ 0 ] ).append( copy_btn );

                /* Append the button to the Options column. */
                $( $( element.children()[ 2 ] ).children()[ 0 ] ).append( delete_btn );

                /* Append the entire entry to the table. */
                table.append( element );
            }

            /* Select the database settings. */
            discordCrypt.set_active_settings_tab( 1 );
        };
    }

    /**
     * @private
     * @desc Opens a file dialog to import a JSON encoded entries file.
     * @param self
     * @return {Function}
     */
    static on_import_database_button_clicked( self ) {
        return () => {
            /* Get the FS module. */
            const fs = require( 'fs' );

            /* Create an input element. */
            let files = require( 'electron' ).remote.dialog.showOpenDialog( {
                title: 'Import Database',
                message: 'Select the configuration file(s) to import',
                buttonLabel: 'Import',
                filters: [ {
                    name: 'Database Entries ( *.json )',
                    extensions: [ 'json' ]
                } ],
                properties: [ 'openFile', 'multiSelections', 'showHiddenFiles', 'treatPackageAsDirectory' ]
            } );

            /* Ignore if no files was selected. */
            if ( !files.length )
                return;

            /* Cache the button. */
            let import_btn = $( '#dc-import-database-btn' );

            /* For reference. */
            let imported = 0;

            /* Update the status. */
            import_btn.text( `Importing ( ${files.length} ) File(s)` );

            /* Loop over every file.  */
            for ( let i = 0; i < files.length; i++ ) {
                let file = files[ i ],
                    data;

                /* Sanity check. */
                if ( !fs.statSync( file ).isFile() )
                    continue;

                /* Read the file. */
                try {
                    data = JSON.parse( fs.readFileSync( file ).toString() );
                }
                catch ( e ) {
                    discordCrypt.log( `Error reading JSON file '${file} ...`, 'warn' );
                    continue;
                }

                /* Make sure the root element of entries exists. */
                if ( !data.discordCrypt_entries || !data.discordCrypt_entries.length )
                    continue;

                /* Iterate all entries. */
                for ( let j = 0; j < data.discordCrypt_entries.length; j++ ) {
                    let e = data.discordCrypt_entries[ j ];

                    /* Skip invalid entries. */
                    if ( !e.id || !e.primary || !e.secondary )
                        continue;

                    /* Determine if to count this as an import or an update which aren't counted. */
                    if ( !self.configFile.passList.hasOwnProperty( e.id ) ) {
                        /* Update the number imported. */
                        imported++;
                    }

                    /* Add it to the configuration file. */
                    self.configFile.passList[ e.id ] = discordCrypt.createPassword( e.primary, e.secondary );
                }
            }

            /* Update the button's text. */
            setTimeout( () => {
                import_btn.text( `Imported (${imported}) ${imported === 1 ? 'Entry' : 'Entries'}` );

                /* Reset the button's text. */
                setTimeout( () => {
                    import_btn.text( 'Import Database(s)' );
                }, 1000 );

            }, 500 );

            /* Determine if to save the database. */
            if ( imported !== 0 ) {
                /* Trigger updating the database entries field. */
                discordCrypt.on_database_settings_tab_button_clicked( self )();

                /* Save the configuration. */
                self.saveConfig();
            }
        };
    }

    /**
     * @private
     * @desc Opens a file dialog to import a JSON encoded entries file.
     * @param self
     * @return {Function}
     */
    static on_export_database_button_clicked( self ) {
        return () => {
            /* Create an input element. */
            let file = require( 'electron' ).remote.dialog.showSaveDialog( {
                title: 'Export Database',
                message: 'Select the destination file',
                buttonLabel: 'Export',
                filters: [ {
                    name: 'Database Entries ( *.json )',
                    extensions: [ 'json' ]
                } ]
            } );

            /* Ignore if no files was selected. */
            if ( !file.length )
                return;

            /* Get the FS module. */
            const fs = require( 'fs' );

            /* Cache the button. */
            let export_btn = $( '#dc-export-database-btn' );

            /* Create the main object for exporting. */
            let data = { discordCrypt_entries: [] },
                entries;

            /* Iterate each entry in the configuration file. */
            for ( let prop in self.configFile.passList ) {
                let e = self.configFile.passList[ prop ];

                /* Insert the entry to the list. */
                data.discordCrypt_entries.push( {
                    id: prop,
                    primary: e.primary,
                    secondary: e.secondary
                } );
            }

            /* Update the entry count. */
            entries = data.discordCrypt_entries.length;

            try {
                /* Try writing the file. */
                fs.writeFileSync( file, JSON.stringify( data, null, '    ' ) );

                /* Update the button's text. */
                export_btn.text( `Exported (${entries}) ${entries === 1 ? 'Entry' : 'Entries'}` );
            }
            catch ( e ) {
                /* Log an error. */
                discordCrypt.log( `Error exporting entries: ${e.toString()}`, 'error' );

                /* Update the button's text. */
                export_btn.text( 'Error: See Console' );
            }

            /* Reset the button's text. */
            setTimeout( () => {
                export_btn.text( 'Export Database' );
            }, 1000 );
        };
    }

    /**
     * @private
     * @desc Clears all entries in the database.
     * @param self
     * @return {Function}
     */
    static on_clear_entries_button_clicked( self ) {
        return () => {
            /* Cache the button. */
            let erase_entries_btn = $( '#dc-erase-entries-btn' );

            /* Remove all entries. */
            self.configFile.passList = {};

            /* Clear the table. */
            $( '#dc-database-entries' ).html( '' );

            /* Save the database. */
            self.saveConfig();

            /* Update the button's text. */
            erase_entries_btn.text( 'Cleared Entries' );

            /* Reset the button's text. */
            setTimeout( () => {
                erase_entries_btn.text( 'Erase Entries' );
            }, 1000 );
        };
    }

    /**
     * @private
     * @desc Closes the settings menu.
     */
    static on_settings_close_button_clicked() {
        /* Select the plugin settings. */
        discordCrypt.set_active_settings_tab( 0 );

        /* Hide main background. */
        $( '#dc-overlay' ).css( 'display', 'none' );

        /* Hide the main settings menu. */
        $( '#dc-overlay-settings' ).css( 'display', 'none' );
    }

    /**
     * @private
     * @desc Saves all settings.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_save_settings_button_clicked( /* discordCrypt */ self ) {
        return () => {

            /* Cache jQuery results. */
            let dc_primary_cipher = $( '#dc-primary-cipher' ),
                dc_secondary_cipher = $( '#dc-secondary-cipher' ),
                dc_master_password = $( '#dc-master-password' );

            /* Update all settings from the settings panel. */
            self.configFile.encodeMessageTrigger = $( '#dc-settings-encrypt-trigger' ).val();
            self.configFile.timedMessageExpires = $( '#dc-settings-timed-expire' ).val();
            self.configFile.encryptBlockMode = $( '#dc-settings-cipher-mode' ).val();
            self.configFile.defaultPassword = $( '#dc-settings-default-pwd' ).val();
            self.configFile.encryptScanDelay = $( '#dc-settings-scan-delay' ).val();
            self.configFile.paddingMode = $( '#dc-settings-padding-mode' ).val();
            self.configFile.useEmbeds = $( '#dc-embed-enabled' ).is( ':checked' );
            self.configFile.encryptMode = discordCrypt
                .cipherStringToIndex( dc_primary_cipher.val(), dc_secondary_cipher.val() );

            dc_primary_cipher.val( discordCrypt.cipherIndexToString( self.configFile.encryptMode, false ) );
            dc_secondary_cipher.val( discordCrypt.cipherIndexToString( self.configFile.encryptMode, true ) );

            /* Handle master password updates if necessary. */
            if ( dc_master_password.val() !== '' ) {
                let password = dc_master_password.val();

                /* Reset the password field. */
                dc_master_password.val( '' );

                /* Hash the password. */
                discordCrypt.scrypt
                (
                    Buffer.from( password ),
                    Buffer.from( discordCrypt.whirlpool( password, true ), 'hex' ),
                    32,
                    4096,
                    8,
                    1,
                    ( error, progress, pwd ) => {
                        if ( error ) {
                            /* Alert the user. */
                            _alert(
                                'DiscordCrypt Error',
                                'Error setting the new database password. Check the console for more info.'
                            );

                            discordCrypt.log( error.toString(), 'error' );
                            return true;
                        }

                        if ( pwd ) {
                            /* Now update the password. */
                            self.masterPassword = Buffer.from( pwd, 'hex' );

                            /* Save the configuration file and update the button text. */
                            self.saveSettings( $( '#dc-settings-save-btn' ) );
                        }

                        return false;
                    }
                );
            }
            else {
                /* Save the configuration file and update the button text. */
                self.saveSettings( $( '#dc-settings-save-btn' ) );
            }
        };
    }

    /**
     * @private
     * @desc Resets the user settings to their default values.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_reset_settings_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Resets the configuration file and update the button text. */
            self.resetSettings( $( '#dc-settings-reset-btn' ) );

            /* Update all settings from the settings panel. */
            $( '#dc-secondary-cipher' ).val( discordCrypt.cipherIndexToString( self.configFile.encryptMode, true ) );
            $( '#dc-primary-cipher' ).val( discordCrypt.cipherIndexToString( self.configFile.encryptMode, false ) );
            $( '#dc-settings-cipher-mode' ).val( self.configFile.encryptBlockMode.toLowerCase() );
            $( '#dc-settings-padding-mode' ).val( self.configFile.paddingMode.toLowerCase() );
            $( '#dc-settings-encrypt-trigger' ).val( self.configFile.encodeMessageTrigger );
            $( '#dc-settings-timed-expire' ).val( self.configFile.timedMessageExpires );
            $( '#dc-settings-default-pwd' ).val( self.configFile.defaultPassword );
            $( '#dc-settings-scan-delay' ).val( self.configFile.encryptScanDelay );
            $( '#dc-embed-enabled' ).prop( 'checked', self.configFile.useEmbeds );
            $( '#dc-master-password' ).val( '' );
        };
    }

    /**
     * @private
     * @desc Restarts the app by performing a window.location.reload()
     */
    static on_restart_now_button_clicked() {
        /* Window reload is simple enough. */
        location.reload();
    }

    /**
     * @private
     * @desc Closes the upload available panel.
     */
    static on_restart_later_button_clicked() {
        /* Hide the update and changelog. */
        $( '#dc-overlay' ).css( 'display', 'none' );
        $( '#dc-update-overlay' ).css( 'display', 'none' );
    }

    /**
     * @private
     * @desc Switches assets to the Info tab.
     */
    static on_info_tab_button_clicked() {
        /* Switch to tab 0. */
        discordCrypt.set_active_exchange_tab( 0 );
    }

    /**
     * @private
     * @desc Switches assets to the Key Exchange tab.
     */
    static on_exchange_tab_button_clicked() {
        /* Switch to tab 1. */
        discordCrypt.set_active_exchange_tab( 1 );
    }

    /**
     * @private
     * @desc Switches assets to the Handshake tab.
     */
    static on_handshake_tab_button_clicked() {
        /* Switch to tab 2. */
        discordCrypt.set_active_exchange_tab( 2 );
    }

    /**
     * @private
     * @desc Closes the key exchange menu.
     */
    static on_close_exchange_button_clicked() {
        /* Hide main background. */
        $( '#dc-overlay' ).css( 'display', 'none' );

        /* Hide the entire exchange key menu. */
        $( '#dc-overlay-exchange' ).css( 'display', 'none' );
    }

    /**
     * @private
     * @desc Opens the key exchange menu.
     */
    static on_open_exchange_button_clicked() {
        /* Show background. */
        $( '#dc-overlay' ).css( 'display', 'block' );

        /* Show main menu. */
        $( '#dc-overlay-exchange' ).css( 'display', 'block' );
    }

    /**
     * @private
     * @desc Generates and sends a new public key.
     */
    static on_quick_send_public_key_button_clicked() {
        /* Don't bother opening a menu. Just generate the key. */
        $( '#dc-keygen-gen-btn' ).click();

        /* Now send it. */
        $( '#dc-keygen-send-pub-btn' ).click();
    }

    /**
     * @private
     * @desc Switches the key lengths to their correct values.
     */
    static on_exchange_algorithm_changed() {
        /* Variable bit lengths. */
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();

        /* Cache jQuery results. */
        let dc_keygen_method = $( '#dc-keygen-method' ),
            dc_keygen_algorithm = $( '#dc-keygen-algorithm' );

        /* Clear the old select list. */
        $( '#dc-keygen-algorithm option' ).each( ( function () {
            $( this ).remove();
        } ) );

        /* Repopulate the entries. */
        switch ( dc_keygen_method.val() )
        {
        case 'dh':
            for ( let i = 0; i < dh_bl.length; i++ ) {
                let v = dh_bl[ i ];
                dc_keygen_algorithm.append( new Option( v, v, i === ( dh_bl.length - 1 ) ) );
            }
            break;
        case 'ecdh':
            for ( let i = 0; i < ecdh_bl.length; i++ ) {
                let v = ecdh_bl[ i ];
                $( '#dc-keygen-algorithm' ).append( new Option( v, v, i === ( ecdh_bl.length - 1 ) ) );
            }
            break;
        default:
            return;
        }
    }

    /**
     * @private
     * @desc Generates a new key pair using the selected algorithm.
     */
    static on_generate_new_key_pair_button_clicked() {
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();
        let max_salt_len = 32, min_salt_len = 16, salt_len;
        let index, raw_buffer, pub_buffer;
        let key, crypto = require( 'crypto' );

        let dc_keygen_method = $( '#dc-keygen-method' ),
            dc_keygen_algorithm = $( '#dc-keygen-algorithm' );

        /* Get the current algorithm. */
        switch ( dc_keygen_method.val() ) {
        case 'dh':
            /* Generate a new Diffie-Hellman RSA key from the bit size specified. */
            key = discordCrypt.generateDH( parseInt( dc_keygen_algorithm.val() ) );

            /* Calculate the index number starting from 0. */
            index = dh_bl.indexOf( parseInt( dc_keygen_algorithm.val() ) );
            break;
        case 'ecdh':
            /* Generate a new Elliptic-Curve Diffie-Hellman key from the bit size specified. */
            key = discordCrypt.generateECDH( parseInt( dc_keygen_algorithm.val() ) );

            /* Calculate the index number starting from dh_bl.length. */
            index = ( ecdh_bl.indexOf( parseInt( dc_keygen_algorithm.val() ) ) + dh_bl.length );
            break;
        default:
            /* Should never happen. */
            return;
        }

        /* Sanity check. */
        if (
            !key ||
            key === undefined ||
            typeof key.getPrivateKey === 'undefined' ||
            typeof key.getPublicKey === 'undefined'
        )
            return;

        /* Copy the private key to this instance. */
        discordCrypt.privateExchangeKey = key;

        /*****************************************************************************************
         *   [ PUBLIC PAYLOAD STRUCTURE ]
         *   +0x00 - Algorithm + Bit size [ 0-6 = DH ( 768, 1024, 1536, 2048, 3072, 4096, 8192 ) |
         *                                  7-12 = ECDH ( 224, 256, 384, 409, 521, 571 ) ]
         *   +0x01 - Salt length
         *   +0x02 - Salt[ Salt.length ]
         *   +0x02 + Salt.length - Public key
         ****************************************************************************************/

        /* Calculate a random salt length. */
        salt_len = ( parseInt( crypto.randomBytes( 1 ).toString( 'hex' ), 16 ) % ( max_salt_len - min_salt_len ) ) +
            min_salt_len;

        /* Copy the buffer. */
        pub_buffer = Buffer.from(
            key.getPublicKey( 'hex', dc_keygen_method.val() === 'ecdh' ?
                'compressed' :
                undefined
            ),
            'hex'
        );

        /* Create a blank payload. */
        raw_buffer = Buffer.alloc( 2 + salt_len + pub_buffer.length );

        /* Write the algorithm index. */
        raw_buffer.writeInt8( index, 0 );

        /* Write the salt length. */
        raw_buffer.writeInt8( salt_len, 1 );

        /* Generate a random salt and copy it to the buffer. */
        crypto.randomBytes( salt_len ).copy( raw_buffer, 2 );

        /* Copy the public key to the buffer. */
        pub_buffer.copy( raw_buffer, 2 + salt_len );

        /* Get the public key then display it. */
        $( '#dc-pub-key-ta' ).val( raw_buffer.toString( 'hex' ) );

        /* Get the private key then display it. */
        $( '#dc-priv-key-ta' ).val( key.getPrivateKey( 'hex' ) );
    }

    /**
     * @private
     * @desc Clears any public and private keys generated.
     */
    static on_keygen_clear_button_clicked() {
        /* Clear the key textareas. */
        $( '#dc-pub-key-ta' ).val( '' );
        $( '#dc-priv-key-ta' ).val( '' );
    }

    /**
     * @private
     * @desc Sends the currently generate public key in the correct format.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_keygen_send_public_key_button_clicked( /* discordCrypt */ self ) {
        return () => {

            /* Cache jQuery results. */
            let dc_pub_key_ta = $( '#dc-pub-key-ta' );

            /* Don't bother if it's empty. */
            if ( dc_pub_key_ta.val() === '' )
                return;

            /* The text area stores a hex encoded binary. Convert it to a buffer prior to encoding. */
            let message = Buffer.from( dc_pub_key_ta.val(), 'hex' );

            /* Add the header to the message and encode it. */
            message = self.encodedKeyHeader + discordCrypt.substituteMessage( message, true );

            /* Split the message by adding a new line every 32 characters like a standard PGP message. */
            let formatted_message = message.replace( /(.{32})/g, ( e ) => {
                return `${e}\n`
            } );

            /* Calculate the algorithm string. */
            let algo_str = `${$( '#dc-keygen-method' ).val() !== 'ecdh' ? 'DH-' : 'ECDH-'}` +
                `${$( '#dc-keygen-algorithm' ).val()}`;

            /* Construct header & footer elements. */
            let header = `-----BEGIN ${algo_str} PUBLIC KEY-----`,
                footer = `-----END ${algo_str} PUBLIC KEY----- | v${self.getVersion().replace( '-debug', '' )}`;

            /* Send the message. */
            discordCrypt.dispatchMessage(
                self.configFile.useEmbeds,
                formatted_message,
                header,
                footer,
                0x720000,
                '',
                undefined,
                self.cachedModules,
                self.configFile.timedMessages,
                self.configFile.timedMessageExpires
            );

            /* Save the configuration file and store the new message. */
            self.saveConfig();

            /* Update the button text & reset after 1 second.. */
            $( '#dc-keygen-send-pub-btn' ).text( 'Sent The Public Key!' );

            setTimeout( ( function () {
                $( '#dc-keygen-send-pub-btn' ).text( 'Send Public Key' );
            } ), 1000 );
        };
    }

    /**
     * @private
     * @desc Pastes what is stored in the clipboard to the handshake public key field.
     */
    static on_handshake_paste_public_key_button_clicked() {
        $( '#dc-handshake-ppk' ).val( require( 'electron' ).clipboard.readText() );
    }

    /**
     * @private
     * @desc Computes a shared secret and generates passwords based on a DH/ECDH key exchange.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_handshake_compute_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let value, algorithm, payload, salt_len, salt, user_salt_len, user_salt;
            let isUserSaltPrimary;

            /* Cache jQuery results. */
            let dc_pub_key_ta = $( '#dc-pub-key-ta' ),
                dc_priv_key_ta = $( '#dc-priv-key-ta' ),
                dc_handshake_ppk = $( '#dc-handshake-ppk' ),
                dc_handshake_compute_btn = $( '#dc-handshake-compute-btn' );

            /* Provide some way of showing the user the result without actually giving it away. */
            function displaySecret( input_hex ) {
                const charset = discordCrypt.getBraille().splice( 16, 64 );
                let output = '';

                for ( let i = 0; i < parseInt( input_hex.length / 2 ); i++ )
                    output += charset[ parseInt( input_hex.substr( i * 2, 2 ) ) & ( charset.length - 1 ) ];

                return output;
            }

            /* Skip if no public key was entered. */
            if ( !dc_handshake_ppk.val() || !dc_handshake_ppk.val().length )
                return;

            /* Skip if the user hasn't generated a key of their own. */
            if ( !dc_pub_key_ta.val() || !dc_pub_key_ta.val().length ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'You Didn\'t Generate A Key!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Check if the message header is valid. */
            if (
                dc_handshake_ppk.val().replace( /\r?\n|\r/g, "" )
                    .slice( 0, 4 ) !== self.encodedKeyHeader
            )
                return;

            /* Snip off the header. */
            let blob = dc_handshake_ppk.val().replace( /\r?\n|\r/g, "" ).slice( 4 );

            /* Skip if invalid braille encoded message. */
            if ( !discordCrypt.isValidBraille( blob ) )
                return;

            try {
                /* Decode the message. */
                value = Buffer.from( discordCrypt.substituteMessage( blob ), 'hex' );
            }
            catch ( e ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'Invalid Public Key!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Check the algorithm they're using is the same as ours. */
            algorithm = value.readInt8( 0 );

            /* Check the algorithm is valid. */
            if ( !discordCrypt.isValidExchangeAlgorithm( algorithm ) ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'Invalid Algorithm!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Read the user's generated public key. */
            let user_pub_key = Buffer.from( dc_pub_key_ta.val(), 'hex' );

            /* Check the algorithm used is the same as ours. */
            if ( user_pub_key.readInt8( 0 ) !== algorithm ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'Mismatched Algorithm!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Update the algorithm text. */
            $( '#dc-handshake-algorithm' ).text(
                `Exchange Algorithm: ${discordCrypt.indexToExchangeAlgorithmString( algorithm )}`
            );

            /* Get the salt length. */
            salt_len = value.readInt8( 1 );

            /* Make sure the salt length is valid. */
            if ( salt_len < 16 || salt_len > 32 ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'Invalid Salt Length!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Read the public salt. */
            salt = Buffer.from( value.subarray( 2, 2 + salt_len ) );

            /* Read the user's salt length. */
            user_salt_len = user_pub_key.readInt8( 1 );

            /* Read the user salt. */
            user_salt = Buffer.from( user_pub_key.subarray( 2, 2 + user_salt_len ) );

            /* Update the salt text. */
            $( '#dc-handshake-salts' ).text(
                `Salts: [ ${displaySecret( salt.toString( 'hex' ) )}, ` +
                `${displaySecret( user_salt.toString( 'hex' ) )} ]`
            );

            /* Read the public key and convert it to a hex string. */
            payload = Buffer.from( value.subarray( 2 + salt_len ) ).toString( 'hex' );

            /* Return if invalid. */
            if ( !discordCrypt.privateExchangeKey || discordCrypt.privateExchangeKey === undefined ||
                typeof discordCrypt.privateExchangeKey.computeSecret === 'undefined' ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'Failed To Calculate Private Key!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Compute the local secret as a hex string. */
            let derived_secret =
                discordCrypt.computeExchangeSharedSecret( discordCrypt.privateExchangeKey, payload, false, false );

            /* Show error and quit if derivation fails. */
            if ( !derived_secret || !derived_secret.length ) {
                /* Update the text. */
                dc_handshake_compute_btn.text( 'Failed To Derive Key!' );
                setTimeout( ( function () {
                    dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                } ), 1000 );
                return;
            }

            /* Display the first 64 characters of it. */
            $( '#dc-handshake-secret' ).text(
                `Derived Secret: [ ${displaySecret( derived_secret.length > 64 ?
                    derived_secret.substring( 0, 64 ) :
                    derived_secret )
                } ]`
            );

            /* We have two salts. We can't know which one is our primary salt so just do a simple check on which
             Salt32 is bigger. */
            if ( user_salt_len === salt_len ) {
                for ( let i = 2; i < parseInt( user_salt_len / 4 ); i += 4 ) {
                    let usl = user_salt.readUInt32BE( i ), sl = salt.readUInt32BE( i );

                    if ( usl === sl )
                        continue;

                    isUserSaltPrimary = usl > sl;
                    break;
                }

                /* Salts are equal, should never happen. */
                if ( isUserSaltPrimary === undefined ) {
                    /* Update the text. */
                    dc_handshake_compute_btn.text( 'Both Salts Are Equal ?!' );
                    setTimeout(
                        ( function () {
                            dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                        } ),
                        1000
                    );
                    return;
                }
            }
            else
                isUserSaltPrimary = user_salt_len > salt_len;

            /* Create hashed salt from the two user-generated salts. */
            let primary_hash = Buffer.from(
                discordCrypt.sha512( isUserSaltPrimary ? user_salt : salt, true ),
                'hex'
            );
            let secondary_hash = Buffer.from(
                discordCrypt.whirlpool( isUserSaltPrimary ? salt : user_salt, true ),
                'hex'
            );

            /* Global progress for async callbacks. */
            let primary_progress = 0, secondary_progress = 0;

            /* Calculate the primary key. */
            discordCrypt.scrypt(
                Buffer.from( derived_secret + secondary_hash.toString( 'hex' ), 'hex' ),
                primary_hash,
                256,
                3072,
                16,
                2,
                ( error, progress, key ) => {
                    if ( error ) {
                        /* Update the text. */
                        dc_handshake_compute_btn.text( 'Failed Generating Primary Key!' );
                        setTimeout(
                            ( function () {
                                dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                            } ),
                            1000
                        );
                        return true;
                    }

                    /* Update progress. */
                    if ( progress ) {
                        primary_progress = progress * 50;

                        $( '#dc-exchange-status' )
                            .css( 'width', `${parseInt( primary_progress + secondary_progress )}%` );
                    }

                    if ( key ) {
                        /* Generate a quality report and apply the password. */
                        $( '#dc-handshake-prim-lbl' ).text( `Primary Key: ( Quality - ${
                            discordCrypt.entropicBitLength( key.toString( 'base64' ) )
                        } Bits )` );
                        $( '#dc-handshake-primary-key' ).val( key.toString( 'base64' ) );

                        /* Since more iterations are done for the primary key, this takes 4x as long thus will
                           always finish second. We can thus restore the original Generate text for the button once
                           this is done. */
                        dc_handshake_compute_btn.text( 'Compute Secret Keys' );

                        /* Now we clear the additional information. */
                        $( '#dc-handshake-algorithm' ).text( '...' );
                        $( '#dc-handshake-secret' ).text( '...' );
                        $( '#dc-handshake-salts' ).text( '...' );
                        $( '#dc-exchange-status' ).css( 'width', '0%' );
                    }

                    return false;
                }
            );

            /* Calculate all salts needed. */
            let primary_salt = isUserSaltPrimary ? user_salt : salt;
            let secondary_salt = isUserSaltPrimary ? salt : user_salt;
            let secondary_password = Buffer.from(
                primary_salt.toString( 'hex' ) + derived_secret + secondary_salt.toString( 'hex' ),
                'hex'
            );

            /* Calculate the secondary key. */
            discordCrypt.scrypt( secondary_password, secondary_hash, 256, 3072, 8, 1, ( error, progress, key ) => {
                if ( error ) {
                    /* Update the text. */
                    dc_handshake_compute_btn.text( 'Failed Generating Secondary Key!' );
                    setTimeout(
                        ( function () {
                            dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                        } ),
                        1000
                    );
                    return true;
                }

                if ( progress ) {
                    secondary_progress = progress * 50;
                    $( '#dc-exchange-status' ).css( 'width', `${parseInt( primary_progress + secondary_progress )}%` );
                }

                if ( key ) {
                    /* Generate a quality report and apply the password. */
                    $( '#dc-handshake-sec-lbl' ).text( `Secondary Key: ( Quality - ${
                        discordCrypt.entropicBitLength( key.toString( 'base64' ) )
                    } Bits )` );
                    $( '#dc-handshake-secondary-key' ).val( key.toString( 'base64' ) );
                }

                return false;
            } );

            /* Update the text. */
            dc_handshake_compute_btn.text( 'Generating Keys ...' );

            /* Finally clear all volatile information. */
            discordCrypt.privateExchangeKey = undefined;
            dc_handshake_ppk.val( '' );
            dc_priv_key_ta.val( '' );
            dc_pub_key_ta.val( '' );
        };
    }

    /**
     * @private
     * @desc Copies the currently generated passwords from a key exchange to the clipboard then erases them.
     */
    static on_handshake_copy_keys_button_clicked() {
        /* Cache jQuery results. */
        let dc_handshake_primary_key = $( '#dc-handshake-primary-key' ),
            dc_handshake_secondary_key = $( '#dc-handshake-secondary-key' );

        /* Don't bother if it's empty. */
        if ( dc_handshake_primary_key.val() === '' ||
            dc_handshake_secondary_key.val() === '' )
            return;

        /* Format the text and copy it to the clipboard. */
        require( 'electron' ).clipboard.writeText(
            `Primary Key: ${dc_handshake_primary_key.val()}\r\n\r\n` +
            `Secondary Key: ${dc_handshake_secondary_key.val()}`
        );

        /* Nuke. */
        dc_handshake_primary_key.val( '' );
        dc_handshake_secondary_key.val( '' );

        /* Update the button text & reset after 1 second. */
        $( '#dc-handshake-cpy-keys-btn' ).text( 'Coped Keys To Clipboard!' );

        setTimeout( ( function () {
            $( '#dc-handshake-cpy-keys-btn' ).text( 'Copy Keys & Nuke' );
            $( '#dc-handshake-prim-lbl' ).text( 'Primary Key: ' );
            $( '#dc-handshake-sec-lbl' ).text( 'Secondary Key: ' );
        } ), 1000 );
    }

    /**
     * @private
     * @desc Applies the generate passwords to the current channel or DM.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_handshake_apply_keys_button_clicked( /* discordCrypt */ self ) {
        return () => {

            /* Cache jQuery results. */
            let dc_handshake_primary_key = $( '#dc-handshake-primary-key' ),
                dc_handshake_secondary_key = $( '#dc-handshake-secondary-key' );

            /* Skip if no primary key was generated. */
            if ( !dc_handshake_primary_key.val() || !dc_handshake_primary_key.val().length )
                return;

            /* Skip if no secondary key was generated. */
            if ( !dc_handshake_secondary_key.val() ||
                !dc_handshake_secondary_key.val().length )
                return;

            /* Create the password object and nuke. */
            let pwd = discordCrypt.createPassword(
                dc_handshake_primary_key.val(),
                dc_handshake_secondary_key.val()
            );
            dc_handshake_primary_key.val( '' );
            dc_handshake_secondary_key.val( '' );

            /* Apply the passwords and save the config. */
            self.configFile.passList[ discordCrypt.getChannelId() ] = pwd;
            self.saveConfig();

            /* Update the text and reset it after 1 second. */
            $( '#dc-handshake-apply-keys-btn' ).text( 'Applied & Saved!' );
            setTimeout( ( function () {
                $( '#dc-handshake-apply-keys-btn' ).text( 'Apply Generated Passwords' );

                /* Reset quality bit length fields. */
                $( '#dc-handshake-prim-lbl' ).text( 'Primary Key: ' );
                $( '#dc-handshake-sec-lbl' ).text( 'Secondary Key: ' );

                /* Hide main background. */
                $( '#dc-overlay' ).css( 'display', 'none' );

                /* Hide the entire exchange key menu. */
                $( '#dc-overlay-exchange' ).css( 'display', 'none' );

                /* Reset the index to the info tab. */
                discordCrypt.set_active_exchange_tab( 0 );
            } ), 1000 );
        }
    }

    /**
     * @private
     * @desc Opens the password editor menu.
     */
    static on_passwd_button_clicked() {
        $( '#dc-overlay' ).css( 'display', 'block' );
        $( '#dc-overlay-password' ).css( 'display', 'block' );
    }

    /**
     * @private
     * @desc Saves the entered passwords for the current channel or DM.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_save_passwords_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let btn = $( '#dc-save-pwd' );

            /* Update the password and save it. */
            self.updatePasswords();

            /* Update the text for the button. */
            btn.text( "Saved!" );

            /* Reset the text for the password button after a 1 second delay. */
            setTimeout( ( function () {
                /* Reset text. */
                btn.text( "Save Password" );

                /* Clear the fields. */
                $( "#dc-password-primary" ).val( '' );
                $( "#dc-password-secondary" ).val( '' );

                /* Close. */
                $( '#dc-overlay' ).css( 'display', 'none' );
                $( '#dc-overlay-password' ).css( 'display', 'none' );
            } ), 1000 );
        };
    }

    /**
     * @private
     * @desc Resets passwords for the current channel or DM to their defaults.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_reset_passwords_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let btn = $( '#dc-reset-pwd' );

            /* Reset the configuration for this user and save the file. */
            delete self.configFile.passList[ discordCrypt.getChannelId() ];
            self.saveConfig();

            /* Update the text for the button. */
            btn.text( "Password Reset!" );

            setTimeout( ( function () {
                /* Reset text. */
                btn.text( "Reset Password" );

                /* Clear the fields. */
                $( "#dc-password-primary" ).val( '' );
                $( "#dc-password-secondary" ).val( '' );

                /* Close. */
                $( '#dc-overlay' ).css( 'display', 'none' );
                $( '#dc-overlay-password' ).css( 'display', 'none' );
            } ), 1000 );
        };
    }

    /**
     * @private
     * @desc Closes the password editor menu.
     */
    static on_cancel_password_button_clicked() {
        /* Clear the fields. */
        $( "#dc-password-primary" ).val( '' );
        $( "#dc-password-secondary" ).val( '' );

        /* Close after a .25 second delay. */
        setTimeout( ( function () {
            /* Close. */
            $( '#dc-overlay' ).css( 'display', 'none' );
            $( '#dc-overlay-password' ).css( 'display', 'none' );
        } ), 250 );
    }

    /**
     * @private
     * @desc Copies the passwords from the current channel or DM to the clipboard.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_copy_current_passwords_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let currentKeys = self.configFile.passList[ discordCrypt.getChannelId() ];

            /* If no password is currently generated, write the default key. */
            if ( !currentKeys ) {
                require( 'electron' ).clipboard.writeText( `Default Password: ${self.configFile.defaultPassword}` );
                return;
            }

            /* Write to the clipboard. */
            require( 'electron' ).clipboard.writeText(
                `Primary Key: ${currentKeys.primary}\r\n\r\nSecondary Key: ${currentKeys.secondary}`
            );

            /* Alter the button text. */
            $( '#dc-cpy-pwds-btn' ).text( 'Copied Keys To Clipboard!' );

            /* Reset the button after 1 second close the prompt. */
            setTimeout( ( function () {
                /* Reset. */
                $( '#dc-cpy-pwds-btn' ).text( 'Copy Current Passwords!' );

                /* Close. */
                $( '#dc-cancel-btn' ).click();
            } ), 1000 );
        };
    }

    /**
     * @private
     * @desc Enables or disables automatic message encryption.
     * @param {discordCrypt} self
     * @returns {Function}
     */
    static on_lock_button_clicked( /* discordCrypt */ self ) {
        return () => {

            /* Cache jQuery results. */
            let dc_lock_btn = $( '#dc-lock-btn' );

            /* Update the icon and toggle. */
            if ( !self.configFile.encodeAll ) {
                dc_lock_btn.attr( 'title', 'Disable Message Encryption' );
                dc_lock_btn.html( Buffer.from( self.lockIcon, 'base64' ).toString( 'utf8' ) );
                self.configFile.encodeAll = true;
            }
            else {
                dc_lock_btn.attr( 'title', 'Enable Message Encryption' );
                dc_lock_btn.html( Buffer.from( self.unlockIcon, 'base64' ).toString( 'utf8' ) );
                self.configFile.encodeAll = false;
            }

            /* Set the button class. */
            $( '.dc-svg' ).attr( 'class', 'dc-svg' );

            /* Save config. */
            self.saveConfig();
        };
    }

    /**
     * @private
     * @desc Sets the active tab index in the settings menu.
     * @param {int} index The index ( 0-1 ) of the page to activate.
     * @example
     * setActiveTab( 1 );
     */
    static set_active_settings_tab( index ) {
        let tab_names = [ 'dc-plugin-settings-tab', 'dc-database-settings-tab' ];
        let tabs = $( '#dc-settings-tab .dc-tab-link' );

        /* Hide all tabs. */
        for ( let i = 0; i < tab_names.length; i++ )
            $( `#${tab_names[ i ]}` ).css( 'display', 'none' );

        /* Deactivate all links. */
        tabs.removeClass( 'active' );

        switch ( index ) {
        case 0:
            $( '#dc-plugin-settings-btn' ).addClass( 'active' );
            $( '#dc-plugin-settings-tab' ).css( 'display', 'block' );
            break;
        case 1:
            $( '#dc-database-settings-btn' ).addClass( 'active' );
            $( '#dc-database-settings-tab' ).css( 'display', 'block' );
            break;
        default:
            break;
        }
    }

    /**
     * @private
     * @desc Sets the active tab index in the exchange key menu.
     * @param {int} index The index ( 0-2 ) of the page to activate.
     * @example
     * setActiveTab( 1 );
     */
    static set_active_exchange_tab( index ) {
        let tab_names = [ 'dc-about-tab', 'dc-keygen-tab', 'dc-handshake-tab' ];
        let tabs = $( '#dc-exchange-tab .dc-tab-link' );

        /* Hide all tabs. */
        for ( let i = 0; i < tab_names.length; i++ )
            $( `#${tab_names[ i ]}` ).css( 'display', 'none' );

        /* Deactivate all links. */
        tabs.removeClass( 'active' );

        switch ( index ) {
        case 0:
            $( '#dc-tab-info-btn' ).addClass( 'active' );
            $( '#dc-about-tab' ).css( 'display', 'block' );
            break;
        case 1:
            $( '#dc-tab-keygen-btn' ).addClass( 'active' );
            $( '#dc-keygen-tab' ).css( 'display', 'block' );
            break;
        case 2:
            $( '#dc-tab-handshake-btn' ).addClass( 'active' );
            $( '#dc-handshake-tab' ).css( 'display', 'block' );
            break;
        default:
            break;
        }
    }

    /* ========================================================= */

    /* ====================== APP UTILITIES ==================== */

    /**
     * @private
     * @desc Returns the name of the plugin file expected on the disk.
     * @returns {string}
     * @example
     * console.log( discordCrypt.getPluginName() );
     * // "discordCrypt.plugin.js"
     */
    static getPluginName() {
        return 'discordCrypt.plugin.js';
    }

    /**
     * @private
     * @desc Check if the plugin is named correctly by attempting to open the plugin file in the BetterDiscord
     *      plugin path.
     * @returns {boolean}
     * @example
     * console.log( discordCrypt.validPluginName() );
     * // False
     */
    static validPluginName() {
        return require( 'fs' )
            .existsSync( require( 'path' )
                .join( discordCrypt.getPluginsPath(), discordCrypt.getPluginName() ) );
    }

    /**
     * @public
     * @desc Returns the platform-specific path to BetterDiscord's plugin directory.
     * @returns {string} The expected path ( which may not exist ) to BetterDiscord's plugin directory.
     * @example
     * console.log( discordCrypt.getPluginsPath() );
     * // "C:\Users\John Doe\AppData\Local/BetterDiscord/plugins"
     */
    static getPluginsPath() {
        const process = require( 'process' );
        return `${process.platform === 'win32' ?
            process.env.APPDATA :
            process.platform === 'darwin' ?
                process.env.HOME + '/Library/Preferences' :
                process.env.HOME + '/.config'}/BetterDiscord/plugins/`;
    }

    /**
     * @public
     * @desc Checks the update server for an encrypted update.
     * @param {UpdateCallback} on_update_callback
     * @returns {boolean}
     * @example
     * checkForUpdate( ( file_data, short_hash, new_version, full_changelog, validated ) => {
     *      console.log( `New Update Available: #${short_hash} - v${new_version}` );
     *      console.log( `Signature is: ${validated ? valid' : 'invalid'}!` );
     *      console.log( `Changelog:\n${full_changelog}` );
     * } );
     */
    static checkForUpdate( on_update_callback ) {
        /* Update URL and request method. */
        const base_url = 'https://gitlab.com/leogx9r/DiscordCrypt/raw/master';
        const update_url = `${base_url}/build/${discordCrypt.getPluginName()}`;
        const signing_key_url = `${base_url}/build/signing-key.pub`;
        const changelog_url = `${base_url}/src/CHANGELOG`;
        const signature_url = `${update_url}.sig`;

        /* Make sure the callback is a function. */
        if ( typeof on_update_callback !== 'function' )
            return false;

        /* Perform the request. */
        try {
            /* Download the update. */
            discordCrypt.__getRequest( update_url, ( statusCode, errorString, data ) => {
                /* Make sure no error occurred. */
                if ( statusCode !== 200 ) {
                    /* Log the error accordingly. */
                    switch ( statusCode ) {
                    case 404:
                        discordCrypt.log( 'Update URL is broken.', 'error' );
                        break;
                    case 403:
                        discordCrypt.log( 'Forbidden request when checking for updates.', 'error' );
                        break;
                    default:
                        discordCrypt.log( `Error while fetching update: ${errorString}`, 'error' );
                        break;
                    }

                    return false;
                }

                /* Get the local file. */
                let localFile = '//META{"name":"discordCrypt"}*//\n';
                try {
                    localFile = require( 'fs' ).readFileSync(
                        require( 'path' ).join(
                            discordCrypt.getPluginsPath(),
                            discordCrypt.getPluginName()
                        )
                    ).toString().replace( '\r', '' );
                }
                catch ( e ) {
                    discordCrypt.log( 'Plugin file could not be locally read. Assuming testing version ...', 'warn' );
                }

                /* Check the first line which contains the metadata to make sure that they're equal. */
                if ( data.split( '\n' )[ 0 ] !== localFile.split( '\n' )[ 0 ] ) {
                    discordCrypt.log( 'Plugin metadata is missing from either the local or update file.', 'error' );
                    return false;
                }

                /* Read the current hash of the plugin and compare them.. */
                let currentHash = discordCrypt.sha256( localFile.replace( '\r', '' ) );
                let hash = discordCrypt.sha256( data.replace( '\r', '' ) );
                let shortHash = Buffer.from( hash, 'base64' )
                    .toString( 'hex' )
                    .slice( 0, 8 );

                /* If the hash equals the retrieved one, no update is needed. */
                if ( hash === currentHash ) {
                    discordCrypt.log( `No Update Needed - #${shortHash}` );
                    return true;
                }

                /* Try parsing a version number. */
                let version_number = '';
                try {
                    version_number = data
                        .match( /((["'])(\d+\.)(\d+\.)(\*|\d+)(["']))/gi )
                        .toString()
                        .replace( /(['|"]*['|"])/g, '' );
                }
                catch ( e ) {
                    discordCrypt.log( 'Failed to locate the version number in the update ...', 'warn' );
                }

                /* Basically the finally step - resolve the changelog & call the callback function. */
                let tryResolveChangelog = ( valid_signature ) => {
                    /* Now get the changelog. */
                    try {
                        /* Fetch the changelog from the URL. */
                        discordCrypt.__getRequest(
                            changelog_url,
                            ( statusCode, errorString, changelog ) => {
                                /* Perform the callback. */
                                on_update_callback(
                                    data,
                                    shortHash,
                                    version_number,
                                    statusCode == 200 ? changelog : '',
                                    valid_signature
                                );
                            }
                        );
                    }
                    catch ( e ) {
                        discordCrypt.log( 'Error fetching the changelog.', 'warn' );

                        /* Perform the callback without a changelog. */
                        on_update_callback( data, shortHash, version_number, '', valid_signature );
                    }
                };

                /* Try validating the signature. */
                try {
                    /* Fetch the signing key. */
                    discordCrypt.__getRequest( signing_key_url, ( statusCode, errorString, signing_key ) => {
                        /* Fetch the detached signature. */
                        discordCrypt.__getRequest( signature_url, ( statusCode, errorString, detached_sig ) => {
                            /* Validate the signature then continue. */
                            discordCrypt.__validatePGPSignature( data, detached_sig, signing_key )
                                .then( ( valid_signature ) => tryResolveChangelog( valid_signature ) );
                        } );
                    } );
                }
                catch( e ) {
                    discordCrypt.log( `Unable to validate the update signature: ${e}`, 'warn' );

                    /* Resolve the changelog anyway even without a valid signature. */
                    tryResolveChangelog( false );
                }

                return true;
            } );
        }
        catch ( ex ) {
            /* Handle failure. */
            discordCrypt.log( `Error while retrieving update: ${ex.toString()}`, 'warn' );
            return false;
        }

        return true;
    }

    /**
     * @private
     * @description Returns the current message ID used by Discord.
     * @returns {string | undefined}
     * @example
     * console.log( discordCrypt.getChannelId() );
     * // "414714693498014617"
     */
    static getChannelId() {
        return window.location.pathname.split( '/' ).pop();
    }

    /**
     * @private
     * @desc Creates a password object using a primary and secondary password.
     * @param {string} primary_password The primary password.
     * @param {string} secondary_password The secondary password.
     * @returns {ChannelPassword} Object containing the two passwords.
     * console.log( discordCrypt.createPassword( 'Hello', 'World' ) );
     * // Object {primary: "Hello", secondary: "World"}
     */
    static createPassword( primary_password, secondary_password ) {
        return { primary: primary_password, secondary: secondary_password };
    }

    /**
     * @private
     * @desc Returns functions to locate exported webpack modules.
     * @returns {WebpackModuleSearcher}
     */
    static getWebpackModuleSearcher() {
        /* [ Credits to the creator. ] */
        const req = typeof( webpackJsonp ) === "function" ?
            webpackJsonp(
                [],
                { '__extra_id__': ( module, _export_, req ) => _export_.default = req },
                [ '__extra_id__' ]
            ).default :
            webpackJsonp.push( [
                [],
                { '__extra_id__': ( _module_, exports, req ) => _module_.exports = req },
                [ [ '__extra_id__' ] ] ]
            );

        delete req.m[ '__extra_id__' ];
        delete req.c[ '__extra_id__' ];

        /**
         * @desc Look through all modules of internal Discord's Webpack and return first one that matches filter
         *      predicate. At first this function will look through already loaded modules cache.
         *      If no loaded modules match, then this function tries to load all modules and match for them.
         *      Loading any module may have unexpected side effects, like changing current locale of moment.js,
         *      so in that case there will be a warning the console.
         *      If no module matches, this function returns `null`.
         *      ou should always try to provide a predicate that will match something,
         *      but your code should be ready to receive `null` in case of changes in Discord's codebase.
         *      If module is ES6 module and has default property, consider default first;
         *      otherwise, consider the full module object.
         * @param {ModulePredicate} filter Predicate to match module
         * @param {boolean} force_load Whether to force load all modules if cached modules don't work.
         * @return {*} First module that matches `filter` or `null` if none match.
         */
        const find = ( filter, force_load ) => {
            for ( let i in req.c ) {
                if ( req.c.hasOwnProperty( i ) ) {
                    let m = req.c[ i ].exports;

                    if ( m && m.__esModule && m.default )
                        m = m.default;

                    if ( m && filter( m ) )
                        return m;
                }
            }

            if ( force_load ) {
                discordCrypt.log( "Couldn't find module in existing cache. Loading all modules.", 'warn' );

                for ( let i = 0; i < req.m.length; ++i ) {
                    try {
                        let m = req( i );
                        if ( m && m.__esModule && m.default && filter( m.default ) )
                            return m.default;
                        if ( m && filter( m ) )
                            return m;
                    }
                    catch ( e ) {
                        discordCrypt.log( `Could not load module index ${i} ...`, 'warn' );
                    }
                }

                discordCrypt.log( 'Cannot find React module.', 'warn' );
            }

            return null;
        };

        /**
         * @desc Look through all modules of internal Discord's Webpack and return first object that has all of
         *      the following prototypes.
         * @param {string[]} protoNames Array of all prototypes to search for.
         * @param {boolean} [force_load] Whether to force load all modules if cached modules don't work.
         * @return {object} First module that matches `protoNames` or `null` if none match.
         */
        const findByUniquePrototypes = ( protoNames, force_load = false ) =>
            find( module => protoNames.every( proto => module.prototype && module.prototype[ proto ] ), force_load );

        /**
         * @desc Look through all modules of internal Discord's Webpack and return first object that has all of the
         *      following properties. You should be ready that in any moment, after Discord update,
         *      this function may start returning `null` (if no such object exists anymore) or even some
         *      different object with the same properties. So you should provide all property names that
         *      you use, and often even some extra properties to make sure you'll get exactly what you want.
         * @param {string[]} propNames Array of property names to look for.
         * @param {boolean} [force_load] Whether to force load all modules if cached modules don't work.
         * @returns {object} First module that matches `propNames` or `null` if none match.
         */
        const findByUniqueProperties = ( propNames, force_load = false ) =>
            find( module => propNames.every( prop => module[ prop ] !== undefined ), force_load );

        /**
         * @desc Look through all modules of internal Discord's Webpack and return first object that has the
         *      `displayName` property with following value. This is useful for searching for React components by
         *      name. Take into account that not all components are exported as modules. Also, there might be
         *      several components with the same name.
         * @param {string} displayName Display name property value to look for.
         * @param {boolean} [force_load] Whether to force load all modules if cached modules don't work.
         * @return {object} First module that matches `displayName` or `null` if none match.
         */
        const findByDisplayName = ( displayName, force_load = false ) =>
            find( module => module.displayName === displayName, force_load );

        /**
         * @desc Look through all modules of internal Discord's Webpack and return the first object that matches
         *      a dispatch token's ID. These usually contain a bundle of `_actionHandlers` used to handle events
         *      internally.
         * @param {int} token The internal token ID number.
         * @param {boolean} [force_load] Whether to force load all modules if cached modules don't work.
         * @return {object} First module that matches the dispatch ID or `null` if none match.
         */
        const findByDispatchToken = ( token, force_load = false ) =>
            find( module =>
                module[ '_dispatchToken' ] !== undefined &&
                module[ '_dispatchToken' ] === `ID_${token}` &&
                module[ '_actionHandlers' ] !== undefined, force_load
            );

        /**
         * @desc Look through all modules of internal Discord's Webpack and return the first object that matches
         *      every dispatcher name provided.
         * @param {string[]} dispatchNames Names of events to search for.
         * @return {object} First module that matches every dispatch name provided or null if no full matches.
         */
        const findByDispatchNames = dispatchNames => {
            for ( let i = 0; i < 500; i++ ) {
                let dispatcher = findByDispatchToken( i );

                if ( !dispatcher )
                    continue;

                if ( dispatchNames.every( prop => dispatcher._actionHandlers.hasOwnProperty( prop ) ) )
                    return dispatcher;
            }
            return null;
        };

        return {
            find,
            findByUniqueProperties,
            findByUniquePrototypes,
            findByDisplayName,
            findByDispatchToken,
            findByDispatchNames
        };
    }

    /**
     * @private
     * @experimental
     * @desc Dumps all function callback handlers with their names, IDs and function prototypes. [ Debug Function ]
     * @param {boolean} [dump_actions] Whether to dump action handlers.
     * @returns {Array} Returns an array of all IDs and identifier callbacks.
     */
    static dumpWebpackModuleCallbacks( dump_actions = true ) {
        const ignored = [
            '_dependencies',
            'initialize',
            'initializeIfNeeded',
            'syncWith',
            'waitFor',
            'hasChangeCallbacks',
            'emitChange',
            'addChangeListener',
            'addConditionalChangeListener',
            'removeChangeListener',
            'getDispatchToken',
            'mustEmitChanges'
        ];

        /* Resolve the finder function. */
        let finder = discordCrypt.getWebpackModuleSearcher().findByDispatchToken;

        /* Create the dumping array. */
        let dump = [];

        /* Iterate over let's say 1000 possible modules ? */
        for ( let i = 0; i < 1000; i++ ) {
            /* Locate the module. */
            let module = finder( i );

            /* Skip if it's invalid. */
            if ( !module )
                continue;

            /* Create an entry in the array. */
            dump[ i ] = {};

            /* Loop over every property in the module. */
            for( let prop in module ) {
                /* Skip ignored. */
                if( ignored.indexOf( prop ) !== -1 )
                    continue;

                /* Dump action handlers. */
                if( prop == '_actionHandlers' || prop == '_changeCallbacks' ) {
                    /* Skip if not required. */
                    if( !dump_actions )
                        continue;

                    dump[ i ][ prop ] = {};

                    /* Loop over every property name in the action handler. */
                    for ( let action in module[ prop ] ) {

                        /* Quick sanity check. */
                        if ( !module._actionHandlers.hasOwnProperty( action ) )
                            continue;

                        /* Assign the module property name and it's basic prototype. */
                        dump[ i ][ prop ][ action ] =
                            module[ prop ][ action ].prototype.constructor.toString().split( '{' )[ 0 ];
                    }
                }
                else {
                    /* Add the actual property name and its prototype. */
                    dump[ i ][ prop ] = module[ prop ].toString().split( '{' )[ 0 ];
                }
            }
        }

        /* Return any found module handlers. */
        return dump;
    }

    /**
     * @private
     * @desc Returns the React modules loaded natively in Discord.
     * @param {CachedModules} cached_modules Cached module parameter for locating standard modules.
     * @returns {ReactModules}
     */
    static getReactModules( cached_modules ) {
        const blacklisted_channel_props = [
            '@me',
            'activity'
        ];

        if ( cached_modules ) {
            return {
                ChannelProps:
                    blacklisted_channel_props.indexOf( discordCrypt.getChannelId() ) !== -1 ?
                        null :
                        discordCrypt.__getElementReactOwner( $( 'form' )[ 0 ] ).props.channel,
                MessageParser: cached_modules.MessageParser,
                MessageController: cached_modules.MessageController,
                MessageActionTypes: cached_modules.MessageActionTypes,
                MessageDispatcher: cached_modules.MessageDispatcher,
                MessageQueue: cached_modules.MessageQueue,
                UserResolver: cached_modules.UserResolver,
                GuildResolver: cached_modules.GuildResolver,
                ChannelResolver: cached_modules.ChannelResolver,
                HighlightJS: cached_modules.HighlightJS,
            };
        }

        return null;
    }

    /**
     * @private
     * @desc Edits the message's content from the channel indicated.
     *      N.B. This does not edit embeds due to the internal code Discord uses.
     * @param {string} channel_id The channel's identifier that the message is located in.
     * @param {string} message_id The message's identifier to delete.
     * @param {string} content The message's new content.
     * @param {CachedModules} cached_modules The internally cached module objects.
     */
    static editMessage( channel_id, message_id, content, cached_modules ) {
        /* Edit the message internally. */
        cached_modules.MessageController.editMessage( channel_id, message_id, { content: content } );
    }

    /**
     * @private
     * @desc Delete the message from the channel indicated.
     * @param {string} channel_id The channel's identifier that the message is located in.
     * @param {string} message_id The message's identifier to delete.
     * @param {CachedModules} cached_modules The internally cached module objects.
     */
    static deleteMessage( channel_id, message_id, cached_modules ) {
        /* Delete the message internally. */
        cached_modules.MessageController.deleteMessage( channel_id, message_id );
    }

    /**
     * @private
     * @desc Sends either an embedded message or an inline message to Discord.
     * @param {boolean} as_embed Whether to dispatch this message as an embed or not.
     * @param {string} main_message The main content to send.
     * @param {string} [message_header] The text to display at the top of an embed.
     * @param {string} [message_footer] The text to display at the bottom of an embed.
     * @param {int} [embedded_color] A hex color used to outline the left side of the embed if applicable.
     * @param {string} [message_content] Message content to be attached above the main message.
     * @param {int} [channel_id] If specified, sends the embedded message to this channel instead of the
     *      current channel.
     * @param {CachedModules} cached_modules Internally cached modules.
     * @param {Array<TimedMessage>} [timed_messages] Array containing timed messages to add this sent message to.
     * @param {int} [expire_time_minutes] The amount of minutes till this message is to be deleted.
     */
    static dispatchMessage(
        as_embed,
        main_message,
        message_header,
        message_footer,
        embedded_color = 0x551A8B,
        message_content = '',
        channel_id = undefined,
        cached_modules = {},
        timed_messages = undefined,
        expire_time_minutes = 0
    ) {
        let mention_everyone = false;

        /* Finds appropriate React modules. */
        const React = discordCrypt.getReactModules( cached_modules );

        /* Parse the message content to the required format if applicable.. */
        if ( typeof message_content === 'string' && message_content.length ) {
            /* Sanity check. */
            if ( React.MessageParser === null ) {
                discordCrypt.log( 'Could not locate the MessageParser module!', 'error' );
                return;
            }

            try {
                /* Parse the message. */
                message_content = React.MessageParser.parse( React.ChannelProps, message_content ).content;

                /* Check for @everyone or @here mentions. */
                if ( message_content.includes( '@everyone' ) || message_content.includes( '@here' ) )
                    mention_everyone = true;
            }
            catch ( e ) {
                message_content = '';
            }
        }
        else
            message_content = '';

        /* Save the Channel ID. */
        let _channel = channel_id !== undefined ? channel_id : discordCrypt.getChannelId();

        /* Sanity check. */
        if ( React.MessageQueue === null ) {
            discordCrypt.log( 'Could not locate the MessageQueue module!', 'error' );
            return;
        }

        /* Sanity check. */
        if ( React.MessageController === null ) {
            discordCrypt.log( 'Could not locate the MessageController module!', 'error' );
            return;
        }

        /* Handles returns for messages. */
        const onDispatchResponse = ( r ) => {
            /* Check if an error occurred and inform Clyde bot about it. */
            if ( !r.ok ) {
                /* Perform Clyde dispatch if necessary. */
                if (
                    r.status >= 400 &&
                    r.status < 500 &&
                    r.body &&
                    !React.MessageController.sendClydeError( _channel, r.body.code )
                ) {
                    /* Log the error in case we can't manually dispatch the error. */
                    discordCrypt.log( `Error sending message: ${r.status}`, 'error' );

                    /* Sanity check. */
                    if ( React.MessageDispatcher === null || React.MessageActionTypes === null ) {
                        discordCrypt.log( 'Could not locate the MessageDispatcher module!', 'error' );
                        return;
                    }

                    React.MessageDispatcher.dispatch( {
                        type: React.MessageActionTypes.ActionTypes.MESSAGE_SEND_FAILED,
                        messageId: _nonce,
                        channelId: _channel
                    } );
                }
            }
            else {
                /* Receive the message normally. */
                React.MessageController.receiveMessage( _channel, r.body );

                /* Add the message to the TimedMessage array. */
                if ( timed_messages && expire_time_minutes > 0 ) {
                    timed_messages.push( {
                        messageId: r.body.id,
                        channelId: _channel,
                        expireTime: Date.now() + ( expire_time_minutes * 60000 )
                    } );
                }
            }
        };

        /* Send this message as an embed. */
        if ( as_embed ) {
            /* Generate a unique nonce for this message. */
            let _nonce = parseInt( require( 'crypto' ).pseudoRandomBytes( 6 ).toString( 'hex' ), 16 );

            /* Create the message embed object and add it to the queue. */
            React.MessageQueue.enqueue(
                {
                    type: 'send',
                    message: {
                        channelId: _channel,
                        nonce: _nonce,
                        content: message_content,
                        mention_everyone: mention_everyone,
                        tts: false,
                        embed: {
                            type: "rich",
                            url: "https://gitlab.com/leogx9r/DiscordCrypt",
                            color: embedded_color || 0x551A8B,
                            output_mime_type: "text/x-html",
                            timestamp: ( new Date() ).toISOString(),
                            encoding: "utf-16",
                            author: {
                                name: message_header || '-----MESSAGE-----',
                                icon_url: 'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/images/encode-logo.png',
                                url: 'https://discord.me/discordCrypt'
                            },
                            footer: {
                                text: message_footer || 'DiscordCrypt',
                                icon_url: 'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/images/app-logo.png',
                            },
                            description: main_message,
                        }
                    }
                },
                onDispatchResponse
            );

            return;
        }

        /* Dispatch the message as normal content. */
        [
            main_message,
            message_content
        ].forEach(
            ( ( value ) => {
                /* Skip empty values. */
                if ( !value.length )
                    return;

                /* Generate a unique nonce for this message. */
                let _nonce = parseInt( require( 'crypto' ).pseudoRandomBytes( 6 ).toString( 'hex' ), 16 );

                /* Create the message object and dispatch it to the queue. */
                React.MessageQueue.enqueue(
                    {
                        type: 'send',
                        message: {
                            channelId: _channel,
                            nonce: _nonce,
                            content: value === message_content ? value : `\`${value}\``,
                            mention_everyone: value === message_content ? mention_everyone : false,
                            tts: false
                        }
                    },
                    onDispatchResponse
                );
            } )
        );
    }

    /**
     * @private
     * @desc Injects a CSS style element into the header tag.
     * @param {string} id The HTML ID string used to identify this CSS style segment.
     * @param {string} css The actual CSS style excluding the <style> tags.
     * @example
     * injectCSS( 'my-css', 'p { font-size: 32px; }' );
     */
    static injectCSS( id, css ) {
        /* Inject into the header tag. */
        $( "head" )
            .append( $( "<style>", { id: id.replace( /^[^a-z]+|[^\w-]+/gi, "" ), html: css } ) )
    }

    /**
     * @private
     * @desc Clears an injected element via its ID tag.
     * @param {string} id The HTML ID string used to identify this CSS style segment.
     * @example
     * clearCSS( 'my-css' );
     */
    static clearCSS( id ) {
        /* Make sure the ID is a valid string. */
        if ( !id || typeof id !== 'string' || !id.length )
            return;

        /* Remove the element. */
        $( `#${id.replace( /^[^a-z]+|[^\w-]+/gi, "" )}` ).remove();
    }

    /**
     * @private
     * @desc Hooks a dispatcher from Discord's internals.
     * @author samogot
     * @param {object} dispatcher The action dispatcher containing an array of _actionHandlers.
     * @param {string} method_name The name of the method to hook.
     * @param {string} options The type of hook to apply. [ 'before', 'after', 'instead', 'revert' ]
     * @param {boolean} [options.once=false] Set to `true` if you want to automatically unhook method after first call.
     * @param {boolean} [options.silent=false] Set to `true` if you want to suppress log messages about patching and
     *      unhooking. Useful to avoid clogging the console in case of frequent conditional hooking/unhooking, for
     *      example from another monkeyPatch callback.
     * @return {function} Returns the function used to cancel the hook.
     */
    static hookDispatcher( dispatcher, method_name, options ) {
        const { before, after, instead, once = false, silent = false } = options;
        const origMethod = dispatcher._actionHandlers[ method_name ];

        const cancel = () => {
            if ( !silent )
                discordCrypt.log( `Unhooking "${method_name}" ...` );
            dispatcher[ method_name ] = origMethod;
        };

        // eslint-disable-next-line consistent-return
        const suppressErrors = ( method, description ) => ( ... params ) => {
            try {
                return method( ... params );
            }
            catch ( e ) {
                discordCrypt.log( `Error occurred in ${description}`, 'error' )
            }
        };

        if ( !dispatcher._actionHandlers[ method_name ].__hooked ) {
            if ( !silent )
                discordCrypt.log( `Hooking "${method_name}" ...` );

            dispatcher._actionHandlers[ method_name ] = function () {
                /**
                 * @interface
                 * @name PatchData
                 * @property {object} thisObject Original `this` value in current call of patched method.
                 * @property {Arguments} methodArguments Original `arguments` object in current call of patched method.
                 *      Please, never change function signatures, as it may cause a lot of problems in future.
                 * @property {cancelPatch} cancelPatch Function with no arguments and no return value that may be called
                 *      to reverse patching of current method. Calling this function prevents running of this callback
                 *      on further original method calls.
                 * @property {function} originalMethod Reference to the original method that is patched. You can use it
                 *      if you need some special usage. You should explicitly provide a value for `this` and any method
                 *      arguments when you call this function.
                 * @property {function} callOriginalMethod This is a shortcut for calling original method using `this`
                 *      and `arguments` from original call.
                 * @property {*} returnValue This is a value returned from original function call. This property is
                 *      available only in `after` callback or in `instead` callback after calling `callOriginalMethod`
                 *      function.
                 */
                const data = {
                    thisObject: this,
                    methodArguments: arguments,
                    cancelPatch: cancel,
                    originalMethod: origMethod,
                    callOriginalMethod: () => data.returnValue =
                        data.originalMethod.apply( data.thisObject, data.methodArguments )
                };
                if ( instead ) {
                    const tempRet =
                        suppressErrors( instead, `${method_name} called hook via 'instead'.` )( data );

                    if ( tempRet !== undefined )
                        data.returnValue = tempRet;
                }
                else {

                    if ( before )
                        suppressErrors( before, `${method_name} called hook via 'before'.` )( data );

                    data.callOriginalMethod();

                    if ( after )
                        suppressErrors( after, `${method_name} called hook via 'after'.` )( data );
                }
                if ( once )
                    cancel();

                return data.returnValue;
            };

            dispatcher._actionHandlers[ method_name ].__hooked = true;
            dispatcher._actionHandlers[ method_name ].__cancel = cancel;
        }
        return dispatcher._actionHandlers[ method_name ].__cancel;
    }

    /**
     * @public
     * @desc Logs a message to the console in HTML coloring. ( For Electron clients. )
     * @param {string} message The message to log to the console.
     * @param {string} method The indication level of the message.
     *      This can be either ['info', 'warn', 'error', 'success']
     *
     * @example
     * log( 'Hello World!' );
     *
     * @example
     * log( 'This is printed in yellow.', 'warn' );
     *
     * @example
     * log( 'This is printed in red.', 'error' );
     *
     * @example
     * log( 'This is printed green.', 'trace' );
     *
     * @example
     * log( 'This is printed green.', 'debug' );
     *
     */
    static log( message, method = "info" ) {
        try {
            console[ method ]( `%c[DiscordCrypt]%c - ${message}`, "color: #7f007f; font-weight: bold;", "" );
        }
        catch ( ex ) {
            console.error( '[DiscordCrypt] - Error logging message ...' );
        }
    }

    /* ========================================================= */

    /* ======================= UTILITIES ======================= */

    /**
     * @private
     * @see https://github.com/signalapp/libsignal-protocol-javascript/blob/master/src/NumericFingerprint.js
     * @desc Generates a 60-character numeric fingerprint for the identity of two pairs.
     * @param {Buffer|Array|string} local_id The local ID.
     * @param {Buffer|Array|string} local_pub_key The key linked to the local ID.
     * @param {Buffer|Array|string} remote_id The remote ID.
     * @param {Buffer|Array|string} remote_pub_key The key linked to the remote ID.
     * @param {number} iterations The number of iterations to perform on each ID pair.
     * @return {string} Returns a 60 character numeric representation of a fingerprint.
     * @example
     *      local_id = Buffer.from( "3d478a260e5d497441f1b61d321b138a", 'hex' );
     *      local_pub_key = Buffer.from( "e77ef936546d73dc5a1c25c8267df649c935168f24827267b1328fd22789eca9", 'hex' );
     *
     *      remote_id = Buffer.from( "2c08a0666e937d115f8b05c82db8a6d0", 'hex' );
     *      remote_pub_key = Buffer.from( "f2f10dc9d0770e3be28298c2d4ab7a856c92bafa99ff7377ec8cd538bd9481ae", 'hex' );
     *
     *      __generateFingerprint( local_id, local_pub_key, remote_id, remote_pub_key, 10000 )
     *      > "22162 70964 05613 66992 07314 11169 62962 97838 72198 67786 04039 39461"
     *
     *      __generateFingerprint( local_id, local_pub_key, remote_id, remote_pub_key, 50000 )
     *      > "30312 92326 56131 09531 10046 93930 82882 61321 64148 11774 32632 62322"
     */
    static __generateFingerprint( local_id, local_pub_key, remote_id, remote_pub_key, iterations = 2000 ) {
        /* Ensures the input variable is a Buffer or can be converted to one else it throws an error. */
        function ensure_buffer( name, variable ) {
            /* Do a type check and throw if it isn't supported. */
            if ( typeof( variable ) !== 'string' && !Buffer.isBuffer( variable ) && !Array.isArray( variable ) )
                throw new Error( `Error for ${name}. Must be a string or buffer.` );

            /* Convert to a buffer. */
            return Buffer.from( variable );
        }

        /* Performs normal iterative hashing by joining an input and a key. */
        function iterate_hash( input, key, count ) {
            /* Loop while iteration count isn't 0. */
            while ( count !== 0 ) {
                /* Update the input with the concatenated hash of the old input + key. */
                input = Buffer.from( discordCrypt.sha256( Buffer.concat( [ input, key ] ), true ), 'hex' );
                count -= 1;
            }

            /* Return the result as a buffer. */
            return input;
        }

        /* Converts a hash input into a 5-character numeric segment. */
        function encode_chunk( hash, offset ) {
            /* Converts 40 bits at once. */
            let chunk = hash[ offset ] * Math.pow( 2, 32 );
            chunk += hash[ offset + 1 ] * Math.pow( 2, 24 );
            chunk += hash[ offset + 2 ] * Math.pow( 2, 16 );
            chunk += hash[ offset + 3 ] * Math.pow( 2, 8 );
            chunk += hash[ offset + 4 ];

            /* Limit to a maximum of 99,999. */
            chunk %= 100000;

            /* Convert this to a string. */
            let s = chunk.toString();

            /* Left-pad with zeros if less than 5 characters. */
            while ( s.length < 5 )
                s = `0${s}`;

            return s;
        }

        /* Converts a 256-bit input hash to a fingerprint identifier. Ignores the last 16 bits. */
        function hash_to_fingerprint( hash ) {
            return `${encode_chunk( hash, 0 )} ${encode_chunk( hash, 5 )} ${encode_chunk( hash, 10 )} ` +
                `${encode_chunk( hash, 15 )} ${encode_chunk( hash, 20 )} ${encode_chunk( hash, 25 )} `;
        }

        /* Resolve both local and remote vars as buffers. */
        local_id = ensure_buffer( 'local_id', local_id );
        local_pub_key = ensure_buffer( 'local_pub_key', local_pub_key );
        remote_id = ensure_buffer( 'remote_id', remote_id );
        remote_pub_key = ensure_buffer( 'remote_pub_key', remote_pub_key );

        /* Ensure the iteration count is valid. */
        if ( typeof iterations !== 'number' )
            throw new Error( 'Invalid value for iteration count.' );

        /* Get the fingerprints for both pairs, sort them and join them all. */
        return [
            hash_to_fingerprint( iterate_hash( local_id, local_pub_key, iterations ) ),
            hash_to_fingerprint( iterate_hash( remote_id, remote_pub_key, iterations ) )
        ]
            .sort()
            .join( '' )
            .trimRight();
    }

    /**
     * @private
     * @desc Verifies an OpenPGP signed message using the public key provided.
     * @param {string} message The raw message.
     * @param {string} signature The ASCII-armored signature in a detached form.
     * @param {string} public_key The ASCII-armored public key.
     * @return {boolean} Returns true if the message is valid.
     */
    static __validatePGPSignature( message, signature, public_key ) {
        if( !window.openpgp )
            return false;

        let options = {
            message: window.openpgp.message.fromText( message ),
            signature: window.openpgp.signature.readArmored( signature ),
            publicKeys: window.openpgp.key.readArmored( public_key ).keys
        };

        return openpgp.verify( options ).then( ( validity ) => validity.signatures[ 0 ].valid );
    }

    /**
     * @public
     * @desc Compresses the input data using ZLIB.
     * @param {string|Buffer} data The input data to compress.
     * @param {string} [format] The format of the input data.
     * @param {string} [outForm] If specified, returns the compressed
     *      data in this format otherwise it returns a Buffer.
     *      Can be either hex, base64, latin1, utf8 or undefined.
     * @return {string|Buffer} The compressed data.
     */
    static __zlibCompress( data, format = 'base64', outForm ) {
        let v = require( 'zlib' ).deflateSync(
            Buffer.isBuffer( data ) ? data : Buffer.from( data, format ),
            { windowBits: 15 }
        );

        return outForm ? v.toString( outForm ) : v;
    }

    /**
     * @public
     * @desc Decompresses an encoded ZLIB package.
     * @param {string|Buffer} data The input data to decompress.
     * @param {string} [format] The format of the input data.
     *      Can be either hex, base64, latin1, utf8 or undefined.
     *      Defaults to Base64.
     * @param {string} [outForm] If specified, returns the decompressed
     *      data in this format otherwise it returns a Buffer.
     *      Can be either hex, base64, latin1, utf8 or undefined.
     * @return {string|Buffer} The original data.
     */
    static __zlibDecompress( data, format = 'base64', outForm = 'utf8' ) {
        let v = require( 'zlib' ).inflateSync(
            Buffer.isBuffer( data ) ? data : Buffer.from( data, format ),
            { windowBits: 15 }
        );

        return outForm ? v.toString( outForm ) : v;
    }

    /**
     * @public
     * @desc Loads all compiled libraries as needed.
     * @param {LibraryDefinition} libraries A list of all libraries to load.
     */
    static __loadLibraries( libraries ) {
        const vm = require( 'vm' );

        /* Inject all compiled libraries based on if they're needed */
        for ( let name in libraries ) {
            let libInfo = libraries[ name ];

            /* Browser code requires a window object to be defined. */
            if ( libInfo.requiresBrowser && typeof window === 'undefined' ) {
                discordCrypt.log( `Skipping loading of browser-required plugin: ${name} ...`, 'warn' );
                continue;
            }

            /* If the module can't be loaded, don't load this library. */
            if ( libInfo.requiresElectron ) {
                try {
                    require( 'electron' );
                }
                catch ( e ) {
                    discordCrypt.log( `Skipping loading of electron-required plugin: ${name} ...`, 'warn' );
                    continue;
                }
            }

            /* Decompress the Base64 code. */
            let code = discordCrypt.__zlibDecompress( libInfo.code );

            /* Determine how to run this. */
            if ( libInfo.requiresBrowser || libInfo.requiresElectron ) {
                /* Run in the current context as it operates on currently defined objects. */
                vm.runInThisContext(
                    code,
                    {
                        filename: name,
                        displayErrors: false
                    }
                );
            }
            else {
                /* Run in a new sandbox and store the result in a global object. */
                global[ name.replace( '.js', '' ) ] =
                    vm.runInNewContext(
                        code,
                        {
                            filename: name,
                            displayErrors: false
                        }
                    );
            }
        }
    }

    /**
     * @private
     * @desc Checks if the plugin should ignore auto-updates.
     *      Usually in a developer environment, a simple symlink is ( or should be ) used to link the current build
     *      file to the plugin path allowing faster deployment.
     * @param {string} version Version string of the plugin to include in the check.
     * @return {boolean} Returns false if the plugin should auto-update.
     */
    static __shouldIgnoreUpdates( version ) {
        const fs = require( 'fs' );
        const path = require( 'path' );
        const plugin_file = path.join( discordCrypt.getPluginsPath(), discordCrypt.getPluginName() );

        return fs.existsSync( plugin_file ) &&
            ( fs.lstatSync( plugin_file ).isSymbolicLink() || version.indexOf( '-debug' ) !== -1 );
    }

    /**
     * @public
     * @desc Performs an HTTP request returns the result to the callback.
     * @param {string} url The URL of the request.
     * @param {GetResultCallback} callback The callback triggered when the request is complete or an error occurs.
     * @private
     */
    static __getRequest( url, callback ) {
        try {
            require( 'request' )( url, ( error, response, result ) => {
                callback( response.statusCode, response.statusMessage, result );
            } );
        }
        catch ( ex ) {
            callback( -1, ex.toString() );
        }
    }

    /**
     * @private
     * @desc Get React component instance of closest owner of DOM element matched by filter.
     * @author noodlebox
     * @param {Element} element DOM element to start react component searching.
     * @param {object} options Filter to match React component by display name.
     *      If `include` if provided, `exclude` value is ignored.
     * @param {string[]} options.include Array of names to allow.
     * @param {string[]} options.exclude Array of names to ignore.
     * @return {object|null} Closest matched React component instance or null if none is matched.
     */
    static __getElementReactOwner(
        element,
        {
            include,
            exclude = [ "Popout", "Tooltip", "Scroller", "BackgroundFlash" ]
        } = {}
    ) {
        if ( element === undefined )
            return undefined;

        /**
         * Get React Internal Instance mounted to DOM element
         * @author noodlebox
         * @param {Element} e DOM element to get React Internal Instance from
         * @return {object|null} Returns React Internal Instance mounted to this element if exists
         */
        const getOwnerReactInstance = e => e[ Object.keys( e ).find( k => k.startsWith( "__reactInternalInstance" ) ) ];
        const excluding = include === undefined;
        const filter = excluding ? exclude : include;

        function classFilter( owner ) {
            const name = owner.type.displayName || owner.type.name || null;
            return ( name !== null && !!( filter.includes( name ) ^ excluding ) );
        }

        for ( let c = getOwnerReactInstance( element ).return; !_.isNil( c ); c = c.return ) {
            if ( _.isNil( c ) )
                continue;

            if ( !_.isNil( c.stateNode ) && !( c.stateNode instanceof HTMLElement ) && classFilter( c ) )
                return c.stateNode;
        }

        return undefined;
    }

    /**
     * @public
     * @desc Returns the exchange algorithm and bit size for the given metadata as well as a fingerprint.
     * @param {string} key_message The encoded metadata to extract the information from.
     * @param {boolean} [header_present] Whether the message's magic string is attached to the input.
     * @returns {PublicKeyInfo|null} Returns the algorithm's bit length and name or null.
     * @example
     * __extractKeyInfo( public_key, true );
     * @example
     * __extractKeyInfo( public_key, false );
     */
    static __extractKeyInfo( key_message, header_present = false ) {
        try {
            let output = [];
            let msg = key_message;

            /* Strip the header if necessary. */
            if ( header_present )
                msg = msg.slice( 4 );

            /* Decode the message to hex. */
            msg = discordCrypt.substituteMessage( msg );

            /* Decode the message to raw bytes. */
            msg = Buffer.from( msg, 'hex' );

            /* Sanity check. */
            if ( !discordCrypt.isValidExchangeAlgorithm( msg[ 0 ] ) )
                return null;

            /* Create a fingerprint for the blob. */
            output[ 'fingerprint' ] = discordCrypt.sha256( msg, true );

            /* Buffer[0] contains the algorithm type. Reverse it. */
            output[ 'bit_length' ] = discordCrypt.indexToAlgorithmBitLength( msg[ 0 ] );
            output[ 'algorithm' ] = discordCrypt.indexToExchangeAlgorithmString( msg[ 0 ] )
                .split( '-' )[ 0 ].toLowerCase();

            return output;
        }
        catch ( e ) {
            return null;
        }
    }

    /**
     * @public
     * @desc Splits the input text into chunks according to the specified length.
     * @param {string} input_string The input string.
     * @param {int} max_length The maximum length of the string before splitting.
     * @returns {Array} An array of split strings.
     * @private
     */
    static __splitStringChunks( input_string, max_length ) {
        /* Sanity check. */
        if ( !max_length || max_length < 0 )
            return input_string;

        /* Calculate the maximum number of chunks this can be split into. */
        const num_chunks = Math.ceil( input_string.length / max_length );
        const ret = new Array( num_chunks );

        /* Split each chunk and add it to the output array. */
        for ( let i = 0, offset = 0; i < num_chunks; ++i, offset += max_length )
            ret[ i ] = input_string.substr( offset, max_length );

        return ret;
    }

    /**
     * @public
     * @desc Determines if the given string is a valid username according to Discord's standards.
     * @param {string} name The name of the user and their discriminator.
     * @returns {boolean} Returns true if the username is valid.
     * @example
     * console.log( __isValidUserName( 'Person#1234' ) ); // true
     * @example
     * console.log( __isValidUserName( 'Person#123' ) ); // false
     * @example
     * console.log( __isValidUserName( 'Person#' ) ); // false
     * @example
     * console.log( __isValidUserName( 'Person1234' ) ); // false
     */
    static __isValidUserName( name ) {
        /* Make sure this is actually a string. */
        if ( typeof name !== 'string' )
            return false;

        /* The name must start with the '@' symbol. */
        if ( name[ 0 ] !== '@' )
            return false;

        /* Iterate through the rest of the name and check for the correct format. */
        for ( let i = 1; i < name.length; i++ ) {
            /* Names can't have spaces or '@' symbols. */
            if ( name[ i ] === ' ' || name[ i ] === '@' )
                return false;

            /* Make sure the discriminator is present. */
            if ( i !== 1 && name[ i ] === '#' ) {
                /* The discriminator is 4 characters long. */
                if ( name.length - i - 1 === 4 ) {
                    try {
                        /* Slice off the discriminator. */
                        let n = name.slice( i + 1, i + 5 );
                        /* Do a weak check to ensure that the Base-10 parsed integer is the same as the string. */
                        return !isNaN( n ) && parseInt( n, 10 ) == n;
                    }
                    catch ( e ) {
                        /* If parsing or slicing somehow fails, this isn't valid. */
                        return false;
                    }
                }
            }
        }

        /* No discriminator found means it's invalid. */
        return false;
    }

    /**
     * @public
     * @desc Extracts all tags from the given message and removes any tagged discriminators.
     * @param {string} message The input message to extract all tags from.
     * @returns {UserTags}
     */
    static __extractTags( message ) {
        let split_msg = message.split( ' ' );
        let cleaned_tags = '', cleaned_msg = '';
        let user_tags = [];

        /* Iterate over each segment and check for usernames. */
        for ( let i = 0, k = 0; i < split_msg.length; i++ ) {
            if ( this.__isValidUserName( split_msg[ i ] ) ) {
                user_tags[ k++ ] = split_msg[ i ];
                cleaned_msg += `${split_msg[ i ].split( '#' )[ 0 ]} `;
            }
            /* Check for @here or @everyone. */
            else if ( [ '@everyone', '@here', '@me' ].indexOf( split_msg[ i ] ) !== -1 ) {
                user_tags[ k++ ] = split_msg[ i ];
                cleaned_msg += `${split_msg[ i ]} `;
            }
            else
                cleaned_msg += `${split_msg[ i ]} `;
        }

        /* Join all tags to a single string. */
        for ( let i = 0; i < user_tags.length; i++ )
            cleaned_tags += `${user_tags[ i ]} `;

        /* Return the parsed message and user tags. */
        return [ cleaned_msg.trim(), cleaned_tags.trim() ];
    }

    /**
     * @public
     * @desc Extracts raw code blocks from a message and returns a descriptive array.
     *      N.B. This does not remove the code blocks from the message.
     * @param {string} message The message to extract all code blocks from.
     * @returns {Array<CodeBlockDescriptor>} Returns an array of CodeBlockDescriptor objects.
     */
    static __extractCodeBlocks( message ) {
        /* This regex only extracts code blocks. */
        let code_block_expr = new RegExp( /^(([ \t]*`{3,4})([^\n]*)([\s\S]+?)(^[ \t]*\2))/gm ),
            inline_block_expr = new RegExp( /(`([^`].*?)`)/g ),
            _matched;

        /* Array to store all the extracted blocks in. */
        let _code_blocks = [];

        /* Loop through each tested RegExp result. */
        while ( ( _matched = code_block_expr.exec( message ) ) ) {
            /* Insert the captured data. */
            _code_blocks.push( {
                start_pos: _matched.index,
                end_pos: _matched.index + _matched[ 1 ].length,
                language: _matched[ 3 ].trim().length === 0 ? 'text' : _matched[ 3 ].trim(),
                raw_code: _matched[ 4 ],
                captured_block: _matched[ 1 ]
            } );
        }

        /* Match inline code blocks. */
        while ( ( _matched = inline_block_expr.exec( message ) ) ) {
            /* Insert the captured data. */
            _code_blocks.push( {
                start_pos: _matched.index,
                end_pos: _matched.index + _matched[ 0 ].length,
                language: 'inline',
                raw_code: message
                    .substr( _matched.index, _matched.index + _matched[ 0 ].length )
                    .split( '`' )[ 1 ],
                captured_block: _matched[ 0 ]
            } );
        }

        return _code_blocks;
    }

    /**
     * @public
     * @desc Extracts raw URLs from a message.
     *      N.B. This does not remove the URLs from the message.
     * @param {string} message The message to extract the URLs from.
     * @returns {Array} Returns an array of URLs detected int the message.
     * @example
     * __extractUrls( 'Hello https://google.com' );
     * //
     * [ 'https://google.com' ]
     */
    static __extractUrls( message ) {
        /* This regex only extracts HTTP/HTTPS/FTP and FILE URLs. */
        let url_expr = new RegExp( /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#/%?=~_|!:,.;]*[-A-Z0-9+&@#/%=~_|])/ig ),
            matched;

        /* Array to store all the extracted URLs in. */
        let urls = [];

        /* Loop through each tested RegExp result. */
        while ( ( matched = url_expr.exec( message ) ) ) {
            /* Insert the captured data. */
            urls.push( matched[ 0 ] );
        }

        return urls;
    }

    /**
     * @public
     * @desc Extracts code blocks from a message and formats them in HTML to the proper format.
     * @param {string} message The message to format code blocks from.
     * @returns {CodeBlockInfo} Returns whether the message contains code blocks and the formatted HTML.
     * @example
     * __buildCodeBlockMessage('```\nHello World!\n```');
     * //
     * {
     *      "code": true,
     *      "html": "<div class=\"markup line-scanned\" data-colour=\"true\" style=\"color: rgb(111, 0, 0);\">
     *                  <pre class=\"hljs\">
     *                      <code class=\"dc-code-block hljs\" style=\"position: relative;\">
     *                          <ol><li>Hello World!</li></ol>
     *                      </code>
     *                  </pre>
     *              </div>"
     * }
     */
    static __buildCodeBlockMessage( message ) {
        try {
            /* Extract code blocks. */
            let _extracted = discordCrypt.__extractCodeBlocks( message );

            /* Wrap the message normally. */
            if ( !_extracted.length )
                return {
                    code: false,
                    html: message
                };

            /* Loop over each expanded code block. */
            for ( let i = 0; i < _extracted.length; i++ ) {
                /* Inline code blocks get styled differently. */
                if ( _extracted[ i ].language !== 'inline' ) {
                    let _lines = '';

                    /* Remove any line-reset characters and split the message into lines. */
                    let _code = _extracted[ i ].raw_code.replace( "\r", '' ).split( "\n" );

                    /* Wrap each line in list elements. */
                    /* We start from position 1 since the regex leaves us with 2 blank lines. */
                    for ( let j = 1; j < _code.length - 1; j++ )
                        _lines += `<li>${_code[ j ]}</li>`;

                    /* Split the HTML message according to the full markdown code block. */
                    message = message.split( _extracted[ i ].captured_block );

                    /* Replace the code with an HTML formatted code block. */
                    message = message.join(
                        '<div class="markup line-scanned" data-colour="true" style="color: rgb(111, 0, 0);">' +
                        `<pre class="hljs"><code class="dc-code-block hljs 
                        ${_extracted[ i ].language === 'text' ? '' : _extracted[ i ].language}"
                         style="position: relative;">` +
                        `<ol>${_lines}</ol></code></pre></div>`
                    );
                }
                else {
                    /* Split the HTML message according to the inline markdown code block. */
                    message = message.split( _extracted[ i ].captured_block );

                    /* Replace the data with a inline code class. */
                    message = message.join( `<code class="inline">${_extracted[ i ].raw_code}</code>` );
                }
            }

            /* Return the parsed message. */
            return {
                code: true,
                html: message
            };
        }
        catch ( e ) {
            /* Wrap the message normally. */
            return {
                code: false,
                html: message
            };
        }
    }

    /**
     * @public
     * @desc Extracts URLs from a message and formats them accordingly.
     * @param {string} message The input message to format URLs from.
     * @param {string} [embed_link_prefix] Optional search link prefix for URLs to embed in frames.
     * @returns {URLInfo} Returns whether the message contains URLs and the formatted HTML.
     */
    static __buildUrlMessage( message, embed_link_prefix ) {
        try {
            /* Extract the URLs. */
            let _extracted = discordCrypt.__extractUrls( message );

            /* Wrap the message normally. */
            if ( !_extracted.length )
                return {
                    url: false,
                    html: message
                };

            /* Loop over each URL and format it. */
            for ( let i = 0; i < _extracted.length; i++ ) {
                let join = '';

                /* Split the message according to the URL and replace it. */
                message = message.split( _extracted[ i ] );

                /* If this is an Up1 host, we can directly embed it. Obviously don't embed deletion links.*/
                if (
                    embed_link_prefix !== undefined &&
                    _extracted[ i ].startsWith( `${embed_link_prefix}/#` ) &&
                    _extracted[ i ].indexOf( 'del?ident=' ) === -1
                )
                    join = `<iframe src=${_extracted[ i ]} width="100%" height="400px"></iframe><br/><br/>`;

                /* Join the message together. */
                message = message.join( `${join}<a target="_blank" href="${_extracted[ i ]}">${_extracted[ i ]}</a>` );
            }

            /* Wrap the message in span tags. */
            return {
                url: true,
                html: `<span>${message}</span>`
            };
        }
        catch ( e ) {
            /* Wrap the message normally. */
            return {
                url: false,
                html: message
            };
        }
    }

    /**
     * @public
     * @desc Returns a string, Buffer() or Array() as a buffered object.
     * @param {string|Buffer|Array} input The input variable.
     * @param {boolean|undefined} [is_input_hex] If set to true, the input is parsed as a hex string. If false, it is
     *      parsed as a Base64 string. If this value is undefined, it is parsed as a UTF-8 string.
     * @returns {Buffer} Returns a Buffer object.
     * @throws {string} Thrown an unsupported type error if the input is neither a string, Buffer or Array.
     */
    static __toBuffer( input, is_input_hex = undefined ) {

        /* No conversion needed, return it as-is. */
        if ( Buffer.isBuffer( input ) )
            return input;

        /* If the message is either a Hex, Base64 or UTF-8 encoded string, convert it to a buffer. */
        if ( typeof input === 'string' )
            return Buffer.from( input, is_input_hex === undefined ? 'utf8' : is_input_hex ? 'hex' : 'base64' );

        /* Convert the Array to a Buffer object first. */
        if ( Array.isArray( input ) )
            return Buffer.from( input );

        /* Throw if an invalid type was passed. */
        throw 'Input is neither an Array(), Buffer() or a string.';
    }

    /**
     * @public
     * @desc Returns the string encoded mime type of a file based on the file extension.
     * @param {string} file_path The path to the file in question.
     * @returns {string} Returns the known file extension's MIME type or "application/octet-stream".
     */
    static __getFileMimeType( file_path ) {
        /* Look up the Mime type from the file extension. */
        let type = require( 'mime-types' ).lookup( require( 'path' ).extname( file_path ) );

        /* Default to an octet stream if it fails. */
        return type === false ? 'application/octet-stream' : type;
    }

    /**
     * @private
     * @desc Attempts to read the clipboard and converts either Images or text to raw Buffer() objects.
     * @returns {ClipboardInfo} Contains clipboard data. May be null.
     */
    static __clipboardToBuffer() {
        /* Request the clipboard object. */
        let clipboard = require( 'electron' ).clipboard;

        /* Sanity check. */
        if ( !clipboard )
            return { mime_type: '', name: '', data: null };

        /* We use original-fs to bypass any file-restrictions ( Eg. ASAR ) for reading. */
        let fs = require( 'original-fs' ),
            path = require( 'path' );

        /* The clipboard must have at least one type available. */
        if ( clipboard.availableFormats().length === 0 )
            return { mime_type: '', name: '', data: null };

        /* Get all available formats. */
        let mime_type = clipboard.availableFormats();
        let data, tmp = '', name = '', is_file = false;

        /* Loop over each format and try getting the data. */
        for ( let i = 0; i < mime_type.length; i++ ) {
            let format = mime_type[ i ].split( '/' );

            /* For types, prioritize images. */
            switch ( format[ 0 ] ) {
            case 'image':
                /* Convert the image type. */
                switch ( format[ 1 ].toLowerCase() ) {
                case 'png':
                    data = clipboard.readImage().toPNG();
                    break;
                case 'bmp':
                case 'bitmap':
                    data = clipboard.readImage().toBitmap();
                    break;
                case 'jpg':
                case 'jpeg':
                    data = clipboard.readImage().toJPEG( 100 );
                    break;
                default:
                    break;
                }
                break;
            case 'text':
                /* Resolve what's in the clipboard. */
                tmp = clipboard.readText();

                try {
                    /* Check if this is a valid file path. */
                    let stat = fs.statSync( tmp );

                    /* Check if this is a file. */
                    if ( stat.isFile() ) {
                        /* Read the file and store the file name. */
                        data = fs.readFileSync( tmp );
                        name = path.basename( tmp );
                        is_file = true;
                    }
                    else {
                        /* This isn't a file. Assume we want to upload the path itself as text. */
                        data = Buffer.from( tmp, 'utf8' );
                    }
                }
                catch ( e ) {
                    /* Convert the text to a buffer. */
                    data = Buffer.from( tmp, 'utf8' );
                }
                break;
            default:
                break;
            }

            /* Keep trying till it has at least a byte of data to return. */
            if ( data && data.length > 0 ) {
                /* If this is a file, try getting the file's MIME type. */
                if ( is_file )
                    mime_type[ i ] = discordCrypt.__getFileMimeType( tmp );

                /* Return the data. */
                return {
                    mime_type: mime_type[ i ],
                    name: name,
                    data: data
                }
            }
        }

        return { mime_type: '', name: '', data: null };
    }

    /**
     * @public
     * @desc Uploads the specified buffer to Up1's format specifications and returns this data to the callback.
     * @param {Buffer} data The input buffer to encrypt.
     * @param {string} mime_type The MIME type of this file.
     * @param {string} file_name The name of this file.
     * @param {Object} sjcl The loaded Stanford Javascript Crypto Library.
     * @param {EncryptedFileCallback} callback The callback function that will be called on error or completion.
     */
    static __up1EncryptBuffer( data, mime_type, file_name, sjcl, callback ) {
        const crypto = require( 'crypto' );

        /* Returns a parameter object from the input seed. */
        function getParams( /* string|Buffer|Array|Uint8Array */ seed ) {
            /* Convert the seed either from a string to Base64 or read it via raw bytes. */
            if ( typeof seed === 'string' )
                seed = sjcl.codec.base64url.toBits( seed );
            else
                seed = sjcl.codec.bytes.toBits( seed );

            /* Compute an SHA-512 hash. */
            let out = sjcl.hash.sha512.hash( seed );

            /* Calculate the output values based on Up1's specs. */
            return {
                seed: seed,
                key: sjcl.bitArray.bitSlice( out, 0, 256 ),
                iv: sjcl.bitArray.bitSlice( out, 256, 384 ),
                ident: sjcl.bitArray.bitSlice( out, 384, 512 )
            }
        }

        /* Converts a string to its UTF-16 equivalent in network byte order. */
        function str2ab( /* string */ str ) {
            /* UTF-16 requires 2 bytes per UTF-8 byte. */
            let buf = Buffer.alloc( str.length * 2 );

            /* Loop over each byte. */
            for ( let i = 0, strLen = str.length; i < strLen; i++ ) {
                /* Write the UTF-16 equivalent in Big Endian. */
                buf.writeUInt16BE( str.charCodeAt( i ), i * 2 );
            }

            return buf;
        }

        try {
            /* Make sure the file size is less than 50 MB. */
            if ( data.length > 50000000 ) {
                callback( 'Input size must be < 50 MB.' );
                return;
            }

            /* Calculate the upload header and append the file data to it prior to encryption. */
            data = Buffer.concat( [
                str2ab( JSON.stringify( { 'mime': mime_type, 'name': file_name } ) ),
                Buffer.from( [ 0, 0 ] ),
                data
            ] );

            /* Convert the file to a Uint8Array() then to SJCL's bit buffer. */
            data = sjcl.codec.bytes.toBits( new Uint8Array( data ) );

            /* Generate a random 512 bit seed and calculate the key and IV from this. */
            let params = getParams( crypto.randomBytes( 64 ) );

            /* Perform AES-256-CCM encryption on this buffer and return an ArrayBuffer() object. */
            data = sjcl.mode.ccm.encrypt( new sjcl.cipher.aes( params.key ), data, params.iv );

            /* Execute the callback. */
            callback(
                null,
                Buffer.from( sjcl.codec.bytes.fromBits( data ) ),
                sjcl.codec.base64url.fromBits( params.ident ),
                sjcl.codec.base64url.fromBits( params.seed )
            );
        }
        catch ( ex ) {
            callback( ex.toString() );
        }
    }

    /**
     * @private
     * @desc Performs AES-256 CCM encryption of the given file and converts it to the expected Up1 format.
     * @param {string} file_path The path to the file to encrypt.
     * @param {Object} sjcl The loaded SJCL library providing AES-256 CCM.
     * @param {EncryptedFileCallback} callback The callback function for when the file has been encrypted.
     * @param {boolean} [randomize_file_name] Whether to randomize the name of the file in the metadata. Default: False.
     */
    static __up1EncryptFile( file_path, sjcl, callback, randomize_file_name = false ) {
        const crypto = require( 'crypto' );
        const path = require( 'path' );
        const fs = require( 'original-fs' );

        try {
            /* Make sure the file size is less than 50 MB. */
            if ( fs.statSync( file_path ).size > 50000000 ) {
                callback( 'File size must be < 50 MB.' );
                return;
            }

            /* Read the file in an async callback. */
            fs.readFile( file_path, ( error, file_data ) => {
                /* Check for any errors. */
                if ( error !== null ) {
                    callback( error.toString() );
                    return;
                }

                /* Encrypt the file data. */
                discordCrypt.__up1EncryptBuffer(
                    file_data,
                    discordCrypt.__getFileMimeType( file_path ),
                    randomize_file_name ?
                        crypto.pseudoRandomBytes( 8 ).toString( 'hex' ) + path.extname( file_path ) :
                        path.basename( file_path ),
                    sjcl,
                    callback
                )
            } );
        }
        catch ( ex ) {
            callback( ex.toString() );
        }
    }

    /**
     * @public
     * @desc Constructs a "random art" noise based BMP image from the input data.
     * @param {Buffer} data The input data to construct the image from.
     * @param {int} width The width of the image in pixels.
     * @param {int} height The height of the image in pixels.
     * @param {boolean} html_encode Whether to encode the image as a Base64 URI or return a raw buffer.
     * @return {Buffer|string}
     */
    static __constructRandomArtImage( data, width, height, html_encode ) {
        /* Construct a random color array from the input data and use the width + height as a salt. */
        const colors = Buffer.from(
            discordCrypt.pbkdf2_sha160(
                data,
                Buffer.alloc( width + height ).fill( 0 ),
                true,
                undefined,
                undefined,
                width * height * 3,
                1000
            ),
            'hex'
        );

        /* Construct a buffer containing the BMP and DIB file headers. */
        let image = Buffer.concat( [
            /** ----------------------------- **/
            /* BMP File Header Magic. */
            Buffer.from( 'BM' ),
            /* Compressed Size */
            Buffer.from( [ 0, 0, 0, 0 ] ),
            /* Reserved */
            Buffer.from( [ 0, 0 ] ),
            /* Reserved */
            Buffer.from( [ 0, 0 ] ),
            /* Pixel Array Offset */
            Buffer.from( [ 26, 0, 0, 0 ] ),
            /** ----------------------------- **/
            /* DIB v2.0 Header Size */
            Buffer.from( [ 12, 0, 0, 0 ] ),
            /* BMP Width */
            Buffer( [ width, 0 ] ),
            /* BMP Height */
            Buffer( [ height, 0 ] ),
            /* Number Of Color Planes */
            Buffer.from( [ 1, 0 ] ),
            /* Bits Per Pixel */
            Buffer.from( [ 24, 0 ] )
            /** ----------------------------- **/
        ] );

        /* Iterate over each row. */
        for ( let i = 0; i < height; i++ ) {
            /* Add the row's pixels and the padding row if required. */
            image = Buffer.concat( [
                image,
                colors.slice( i * height, ( i * height ) + ( width * 3 ) ),
                Buffer.alloc( width % 4 ).fill( 0 )
            ] );
        }

        /* Add the terminator. */
        image = Buffer.concat( [ image, Buffer.from( [ 0 ] ) ] );

        /* Return the result either encoded or as-is. */
        return html_encode ?
            `data:image/bmp;base64,${image.toString( 'base64' )}` :
            image;
    }

    /**
     * @public
     * @desc Uploads raw data to an Up1 service and returns the file URL and deletion key.
     * @param {string} up1_host The host URL for the Up1 service.
     * @param {string} [up1_api_key] The optional API key used for the service.
     * @param {Object} sjcl The loaded SJCL library providing AES-256 CCM.
     * @param {UploadedFileCallback} callback The callback function called on success or failure.
     * @param {ClipboardInfo} [clipboard_data] Optional clipboard data.
     */
    static __up1UploadClipboard( up1_host, up1_api_key, sjcl, callback, clipboard_data = undefined ) {
        /* Get the current clipboard data. */
        let clipboard = clipboard_data === undefined ? discordCrypt.__clipboardToBuffer() : clipboard_data;

        /* Perform sanity checks on the clipboard data. */
        if ( !clipboard.mime_type.length || clipboard.data === null ) {
            callback( 'Invalid clipboard data.' );
            return;
        }

        /* Get a real file name, whether it be random or actual. */
        let file_name = clipboard.name.length === 0 ?
            require( 'crypto' ).pseudoRandomBytes( 16 ).toString( 'hex' ) :
            clipboard.name;

        /* Encrypt the buffer. */
        this.__up1EncryptBuffer(
            clipboard.data,
            clipboard.mime_type,
            file_name,
            sjcl,
            ( error_string, encrypted_data, identity, encoded_seed ) => {
                /* Return if there's an error. */
                if ( error_string !== null ) {
                    callback( error_string );
                    return;
                }

                /* Create a new FormData() object. */
                let form = new ( require( 'form-data' ) )();

                /* Append the ID and the file data to it. */
                form.append( 'ident', identity );
                form.append( 'file', encrypted_data, { filename: 'file', contentType: 'text/plain' } );

                /* Append the API key if necessary. */
                if ( up1_api_key !== undefined && typeof up1_api_key === 'string' )
                    form.append( 'api_key', up1_api_key );

                /* Perform the post request. */
                require( 'request' ).post(
                    {
                        headers: form.getHeaders(),
                        uri: `${up1_host}/up`,
                        body: form
                    },
                    ( err, res, body ) => {
                        try {
                            /* Execute the callback if no error has occurred. */
                            if ( err !== null )
                                callback( err );
                            else {
                                callback(
                                    null,
                                    `${up1_host}/#${encoded_seed}`,
                                    `${up1_host}/del?ident=${identity}&delkey=${JSON.parse( body ).delkey}`,
                                    encoded_seed
                                );
                            }
                        }
                        catch ( ex ) {
                            callback( ex.toString() );
                        }
                    }
                );
            }
        );
    }

    /**
     * @public
     * @desc Uploads the given file path to an Up1 service and returns the file URL and deletion key.
     * @param {string} file_path The path to the file to encrypt.
     * @param {string} up1_host The host URL for the Up1 service.
     * @param {string} [up1_api_key] The optional API key used for the service.
     * @param {Object} sjcl The loaded SJCL library providing AES-256 CCM.
     * @param {UploadedFileCallback} callback The callback function called on success or failure.
     * @param {boolean} [randomize_file_name] Whether to randomize the name of the file in the metadata. Default: False.
     */
    static __up1UploadFile( file_path, up1_host, up1_api_key, sjcl, callback, randomize_file_name = false ) {
        /* Encrypt the file data first. */
        this.__up1EncryptFile(
            file_path,
            sjcl,
            ( error_string, encrypted_data, identity, encoded_seed ) => {
                /* Return if there's an error. */
                if ( error_string !== null ) {
                    callback( error_string );
                    return;
                }

                /* Create a new FormData() object. */
                let form = new ( require( 'form-data' ) )();

                /* Append the ID and the file data to it. */
                form.append( 'ident', identity );
                form.append( 'file', encrypted_data, { filename: 'file', contentType: 'text/plain' } );

                /* Append the API key if necessary. */
                if ( up1_api_key !== undefined && typeof up1_api_key === 'string' )
                    form.append( 'api_key', up1_api_key );

                /* Perform the post request. */
                require( 'request' ).post(
                    {
                        headers: form.getHeaders(),
                        uri: `${up1_host}/up`,
                        body: form
                    },
                    ( err, res, body ) => {
                        try {
                            /* Execute the callback if no error has occurred. */
                            if ( err !== null )
                                callback( err );
                            else {
                                callback(
                                    null,
                                    `${up1_host}/#${encoded_seed}`,
                                    `${up1_host}/del?ident=${identity}&delkey=${JSON.parse( body ).delkey}`,
                                    encoded_seed
                                );
                            }
                        }
                        catch ( ex ) {
                            callback( ex.toString() );
                        }
                    }
                );
            },
            randomize_file_name
        );
    }

    /**
     * @private
     * @desc Attempts to parse an input changelog and returns only the differences between
     *      the current version and the latest version.
     * @param {string} changelog_data The full changelog data.
     * @param {string} current_version The current version currently installed.
     * @return {string} Returns the differences or the full changelog on failure.
     */
    static __tryParseChangelog( changelog_data, current_version ) {
        /**
         * @protected
         * @desc Compares two version numbers in the format x.y.z.
         * @param {string} first The first version string to compare.
         * @param {string} second The second version string to compare against.
         * @return {number} Returns 0 if equal, > 0 if [first > second] and < 0 if [second > first].
         */
        const VersionCompare = ( first, second ) => {
            /* Split the versions into segments. */
            let _first = first.replace( /(\.0+)+$/, '' ).split( '.' );
            let _second = second.replace( /(\.0+)+$/, '' ).split( '.' );

            /* Iterate over the smallest version component lengths. */
            for ( let i = 0; i < Math.min( _first.length, _second.length ); i++ ) {
                /* Compare the first component to the second and check if it's larger. */
                let delta = parseInt( _first[ i ], 10 ) - parseInt( _second[ i ], 10 );

                /* Return a positive number indicating the length. */
                if ( delta )
                    return delta;
            }

            /* Return either 0 or negative indicating the second is equal or greater than the first. */
            return _first.length - _second.length;
        };

        try {
            let result = '';

            /* Capture all versions and sort them from lowest to highest. */
            let versions = changelog_data
                .split( "\r" )
                .join( "" )
                .match( /((Version )(\d+\.)(\d+\.)(\*|\d+))/gm )
                .sort( VersionCompare );

            /* Iterate all versions from the most recent to the lowest. */
            for ( let i = versions.length - 1; i > 0; i-- ) {
                /* Compare the current version against this one. */
                let r = VersionCompare( current_version, versions[ i ] );

                /* Ignore if the current version is greater or equal to the one being checked. */
                if( r > 0 || r === 0 )
                    continue;

                /* Get the full version changes block. */
                let changes = changelog_data.slice(
                    changelog_data.indexOf( versions[ i ] ),
                    changelog_data.indexOf( versions[ i - 1 ] )
                );

                /* Insert the current version info into the changelog result. */
                result += `${versions[ i ]}\n\n`;
                result += changes
                    .replace( versions[ i ], '' )
                    .replace( "\n\n", '' );
            }

            /* Return the result. */
            return result;
        }
        catch ( e ) {
            discordCrypt.log( `Failed to parse the changelog: ${e}`, 'warn' );
        }

        /* Return the full changelog. */
        return changelog_data;
    }

    /* ========================================================= */

    /* =================== CRYPTO PRIMITIVES =================== */

    /**
     * @public
     * @desc Creates a hash of the specified algorithm and returns either a hex-encoded or base64-encoded digest.
     * @param {string|Buffer|Array} message The message to perform the hash on.
     * @param {string} algorithm The specified hash algorithm to use.
     * @param {boolean} [to_hex] If true, converts the output to hex else it converts it to Base64.
     * @param {boolean} hmac If this is true, an HMAC hash is created using a secret.
     * @param {string|Buffer|Array} secret The input secret used for the creation of an HMAC object.
     * @returns {string} Returns either a Base64 or hex string on success and an empty string on failure.
     * @example
     * console.log( __createHash( 'Hello World!', 'sha256', true ) );
     * // "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
     * @example
     * console.log( __createHash( 'Hello World', 'sha256', true, true, 'My Secret' ) );
     * // "852f78f917c4408000a8a94be61687865000bec5b2b77c0704dc5ad73ea06368"
     */
    static __createHash( message, algorithm, to_hex, hmac, secret ) {
        try {
            const crypto = require( 'crypto' );

            /* Create the hash algorithm. */
            const hash = hmac ? crypto.createHmac( algorithm, secret ) :
                crypto.createHash( algorithm );

            /* Hash the data. */
            hash.update( message );

            /* Return the digest. */
            return hash.digest( to_hex ? 'hex' : 'base64' );
        }
        catch ( e ) {
            return '';
        }
    }

    /**
     * @public
     * @desc Computes a key-derivation based on the PBKDF2 standard and returns a hex or base64 encoded digest.
     * @param {string|Buffer|Array} input The input value to hash.
     * @param {string|Buffer|Array} salt The secret value used to derive the hash.
     * @param {boolean} [to_hex] Whether to conver the result to a hex string or a Base64 string.
     * @param {boolean} [is_input_hex] Whether to treat the input as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {boolean} [is_salt_hex] Whether to treat the salt as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {PBKDF2Callback} [callback] The callback function if performing an async request.
     * @param {string} algorithm The name of the hash algorithm to use.
     * @param {int} key_length The length of the desired key in bytes.
     * @param {int} iterations The number of recursive iterations to use to produce the resulting hash.
     * @returns {string} If a callback is not specified, this returns the hex or Base64 result or an empty string on
     *      failure.
     * @example
     * __pbkdf2( 'Hello World!', 'Super Secret', true, undefined, undefined, undefined, 'sha256', 32, 10000 );
     * // "89205432badb5b1e53c7bb930d428afd0f98e5702c4e549ea2da4cfefe8af254"
     * @example
     * __pbkdf2( 'ABC', 'Salty!', true, undefined, undefined, ( e, h ) => { console.log( `Hash: ${h}` ); },
     *      'sha256', 32, 1000 );
     * // Hash: f0e110b17b02006bbbcecb8eb295421c69081a6ecda75c94d55d20759dc295b1
     */
    static __pbkdf2( input, salt, to_hex, is_input_hex, is_salt_hex, callback, algorithm, key_length, iterations ) {
        const crypto = require( 'crypto' );
        let _input, _salt;

        /* Convert necessary data to Buffer objects. */
        if ( typeof input === 'object' ) {
            if ( Buffer.isBuffer( input ) )
                _input = input;
            else if ( Array.isArray )
                _input = Buffer.from( input );
            else
                _input = Buffer.from( input, is_input_hex === undefined ? 'utf8' : is_input_hex ? 'hex' : 'base64' );
        }
        else if ( typeof input === 'string' )
            _input = Buffer.from( input, 'utf8' );

        if ( typeof salt === 'object' ) {
            if ( Buffer.isBuffer( salt ) )
                _salt = salt;
            else if ( Array.isArray )
                _salt = Buffer.from( salt );
            else
                _salt = Buffer.from( salt, is_salt_hex === undefined ? 'utf8' : is_salt_hex ? 'hex' : 'base64' );
        }
        else if ( typeof salt === 'string' )
            _salt = Buffer.from( salt, 'utf8' );

        /* For function callbacks, use the async method else use the synchronous method. */
        if ( typeof callback === 'function' )
            crypto.pbkdf2( _input, _salt, iterations, key_length, algorithm, ( e, key ) => {
                callback( e, !e ? key.toString( to_hex ? 'hex' : 'base64' ) : '' );
            } );
        else
            try {
                return crypto.pbkdf2Sync( _input, _salt, iterations, key_length, algorithm )
                    .toString( to_hex ? 'hex' : 'base64' );
            }
            catch ( e ) {
                throw e;
            }

        return '';
    }

    /**
     * @public
     * @desc Pads or un-pads the input message using the specified encoding format and block size.
     * @param {string|Buffer|Array} message The input message to either pad or unpad.
     * @param {string} padding_scheme The padding scheme used. This can be either: [ ISO1, ISO9, PKC7, ANS2 ]
     * @param {int} block_size The block size that the padding scheme must align the message to.
     * @param {boolean} [is_hex] Whether to treat the message as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {boolean} [remove_padding] Whether to remove the padding applied to the message. If undefined, it is
     *      treated as false.
     * @returns {Buffer} Returns the padded or unpadded message as a Buffer object.
     */
    static __padMessage( message, padding_scheme, block_size, is_hex = undefined, remove_padding = undefined ) {
        let _message, _padBytes;

        /* Returns the number of bytes required to pad a message based on the block size. */
        function __getPaddingLength( totalLength, blockSize ) {
            return totalLength % blockSize === blockSize ? blockSize : blockSize - ( totalLength % blockSize );
        }

        /* Pads a message according to the PKCS #7 / PKCS #5 format. */
        function __PKCS7( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = Buffer.alloc( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Append the number of padding bytes according to PKCS #7 / PKCS #5 format. */
                Buffer.alloc( paddingBytes ).fill( paddingBytes ).copy( padded, message.length );

                /* Return the result. */
                return padded;
            }
            else {
                /* Remove the padding indicated by the last byte. */
                return message.slice( 0, message.length - message.readInt8( message.length - 1 ) );
            }
        }

        /* Pads a message according to the ANSI X9.23 format. */
        function __ANSIX923( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = Buffer.alloc( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Append null-bytes till the end of the message. */
                Buffer.alloc( paddingBytes - 1 ).fill( 0x00 ).copy( padded, message.length );

                /* Append the padding length as the final byte of the message. */
                Buffer.alloc( 1 ).fill( paddingBytes ).copy( padded, message.length + paddingBytes - 1 );

                /* Return the result. */
                return padded;
            }
            else {
                /* Remove the padding indicated by the last byte. */
                return message.slice( 0, message.length - message.readInt8( message.length - 1 ) );
            }
        }

        /* Pads a message according to the ISO 10126 format. */
        function __ISO10126( message, paddingBytes, remove ) {
            const crypto = require( 'crypto' );

            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = Buffer.alloc( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Copy random data to the end of the message. */
                crypto.randomBytes( paddingBytes - 1 ).copy( padded, message.length );

                /* Write the padding length at the last byte. */
                padded.writeUInt8( paddingBytes, message.length + paddingBytes - 1 );

                /* Return the result. */
                return padded;
            }
            else {
                /* Remove the padding indicated by the last byte. */
                return message.slice( 0, message.length - message.readUInt8( message.length - 1 ) );
            }
        }

        /* Pads a message according to the ISO 97971 format. */
        function __ISO97971( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = Buffer.alloc( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Append the first byte as 0x80 */
                Buffer.alloc( 1 ).fill( 0x80 ).copy( padded, message.length );

                /* Fill the rest of the padding with zeros. */
                Buffer.alloc( paddingBytes - 1 ).fill( 0x00 ).copy( message, message.length + 1 );

                /* Return the result. */
                return padded;
            }
            else {

                /* Scan backwards. */
                let lastIndex = message.length - 1;

                /* Find the amount of null padding bytes. */
                for ( ; lastIndex > 0; lastIndex-- )
                    /* If a null byte is encountered, split at this index. */
                    if ( message[ lastIndex ] !== 0x00 )
                        break;

                /* Remove the null-padding. */
                let cleaned = message.slice( 0, lastIndex + 1 );

                /* Remove the final byte which is 0x80. */
                return cleaned.slice( 0, cleaned.length - 1 );
            }
        }

        /* Convert the message to a Buffer object. */
        _message = discordCrypt.__toBuffer( message, is_hex );

        /* Get the number of bytes required to pad this message. */
        _padBytes = remove_padding ? 0 : __getPaddingLength( _message.length, block_size / 8 );

        /* Apply the message padding based on the format specified. */
        switch ( padding_scheme.toUpperCase() ) {
        case 'PKC7':
            return __PKCS7( _message, _padBytes, remove_padding );
        case 'ANS2':
            return __ANSIX923( _message, _padBytes, remove_padding );
        case 'ISO1':
            return __ISO10126( _message, _padBytes, remove_padding );
        case 'ISO9':
            return __ISO97971( _message, _padBytes, remove_padding );
        default:
            return '';
        }
    }

    /**
     * @public
     * @desc Determines whether the passed cipher name is valid.
     * @param {string} cipher The name of the cipher to check.
     * @returns {boolean} Returns true if the cipher name is valid.
     * @example
     * console.log( __isValidCipher( 'aes-256-cbc' ) ); // True
     * @example
     * console.log( __isValidCipher( 'aes-256-gcm' ) ); // True
     * @example
     * console.log( __isValidCipher( 'camellia-256-gcm' ) ); // False
     */
    static __isValidCipher( cipher ) {
        const crypto = require( 'crypto' );
        let isValid = false;

        /* Iterate all valid Crypto ciphers and compare the name. */
        let cipher_name = cipher.toLowerCase();
        crypto.getCiphers().every( ( s ) => {
            /* If the cipher matches, stop iterating. */
            if ( s === cipher_name ) {
                isValid = true;
                return false;
            }

            /* Continue iterating. */
            return true;
        } );

        /* Return the result. */
        return isValid;
    }

    /**
     * @public
     * @desc Converts a given key or iv into a buffer object. Performs a hash of the key it doesn't match the blockSize.
     * @param {string|Buffer|Array} key The key to perform validation on.
     * @param {int} key_size_bits The bit length of the desired key.
     * @param {boolean} [use_whirlpool] If the key length is 512-bits, use Whirlpool or SHA-512 hashing.
     * @returns {Buffer} Returns a Buffer() object containing the key of the desired length.
     */
    static __validateKeyIV( key, key_size_bits = 256, use_whirlpool = undefined ) {
        /* Get the designed hashing algorithm. */
        let keyBytes = key_size_bits / 8;

        /* If the length of the key isn't of the desired size, hash it. */
        if ( key.length !== keyBytes ) {
            let hash;

            /* Get the appropriate hash algorithm for the key size. */
            switch ( keyBytes ) {
            case 8:
                hash = discordCrypt.whirlpool64;
                break;
            case 16:
                hash = discordCrypt.sha512_128;
                break;
            case 20:
                hash = discordCrypt.sha160;
                break;
            case 24:
                hash = discordCrypt.whirlpool192;
                break;
            case 32:
                hash = discordCrypt.sha256;
                break;
            case 64:
                hash = use_whirlpool !== undefined ? discordCrypt.sha512 : discordCrypt.whirlpool;
                break;
            default:
                throw 'Invalid block size specified for key or iv. Only 64, 128, 160, 192, 256 and 512 bit keys' +
                ' are supported.';
            }
            /* Hash the key and return it as a buffer. */
            return Buffer.from( hash( key, true ), 'hex' );
        }
        else
            return Buffer.from( key );
    }

    /**
     * @public
     * @desc Convert the message to a buffer object.
     * @param {string|Buffer|Array} message The input message.
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @returns {Buffer} Returns a Buffer() object containing the message.
     * @throws An exception indicating the input message type is neither an Array(), Buffer() or string.
     */
    static __validateMessage( message, is_message_hex = undefined ) {
        /* Convert the message to a buffer. */
        try {
            return discordCrypt.__toBuffer( message, is_message_hex );
        }
        catch ( e ) {
            throw 'exception - Invalid message type.';
        }
    }

    /**
     * @public
     * @see https://github.com/ricmoo/scrypt-js
     * @desc Performs the Scrypt hash function on the given input.
     * @param {string|Buffer|Array} input The input data to hash.
     * @param {string|Buffer|Array} salt The unique salt used for hashing.
     * @param {int} output_length The desired length of the output in bytes.
     * @param {int} N The work factor variable. Memory and CPU usage scale linearly with this.
     * @param {int} r Increases the size of each hash produced by a factor of 2rK-bits.
     * @param {int} p Parallel factor. Indicates the number of mixing functions to be run simultaneously.
     * @param {ScryptCallback} cb Callback function for progress updates.
     * @returns {boolean} Returns true if successful.
     */
    static scrypt( input, salt, output_length, N = 16384, r = 8, p = 1, cb = null ) {
        let crypto = require( 'crypto' );
        let _in, _salt;

        /* PBKDF2-HMAC-SHA256 Helper. */
        function PBKDF2_SHA256( input, salt, size, iterations ) {
            return crypto.pbkdf2Sync( input, salt, iterations, size, 'sha256' );
        }

        /**
         * @private
         * @desc Mixes rows and blocks via Salsa20/8..
         * @param {Uint32Array} BY Input/output array.
         * @param {int} Yi Size of r * 32.
         * @param {int} r Block size parameter.
         * @param {Uint32Array} x Salsa20 scratchpad for row mixing.
         * @param {Uint32Array} _X Salsa20 scratchpad for block mixing.
         */
        function ScryptRowMix( BY, Yi, r, x, _X ) {
            let i, j, k, l;

            for ( i = 0, j = ( 2 * r - 1 ) * 16; i < 16; i++ )
                _X[ i ] = BY[ j + i ];

            for ( i = 0; i < 2 * r; i++ ) {
                for ( j = 0, k = i * 16; j < 16; j++ )
                    _X[ j ] ^= BY[ k + j ];

                for ( j = 0; j < 16; j++ )
                    x[ j ] = _X[ j ];

                /**
                 * @desc Rotates [a] by [b] bits to the left.
                 * @param {int} a The base value.
                 * @param {int} b The number of bits to rotate [a] to the left by.
                 * @return {number}
                 */
                let R = ( a, b ) => {
                    return ( a << b ) | ( a >>> ( 32 - b ) );
                };

                for ( j = 8; j > 0; j -= 2 ) {
                    x[ 0x04 ] ^= R( x[ 0x00 ] + x[ 0x0C ], 0x07 );
                    x[ 0x08 ] ^= R( x[ 0x04 ] + x[ 0x00 ], 0x09 );
                    x[ 0x0C ] ^= R( x[ 0x08 ] + x[ 0x04 ], 0x0D );
                    x[ 0x00 ] ^= R( x[ 0x0C ] + x[ 0x08 ], 0x12 );
                    x[ 0x09 ] ^= R( x[ 0x05 ] + x[ 0x01 ], 0x07 );
                    x[ 0x0D ] ^= R( x[ 0x09 ] + x[ 0x05 ], 0x09 );
                    x[ 0x01 ] ^= R( x[ 0x0D ] + x[ 0x09 ], 0x0D );
                    x[ 0x05 ] ^= R( x[ 0x01 ] + x[ 0x0D ], 0x12 );
                    x[ 0x0E ] ^= R( x[ 0x0A ] + x[ 0x06 ], 0x07 );
                    x[ 0x02 ] ^= R( x[ 0x0E ] + x[ 0x0A ], 0x09 );
                    x[ 0x06 ] ^= R( x[ 0x02 ] + x[ 0x0E ], 0x0D );
                    x[ 0x0A ] ^= R( x[ 0x06 ] + x[ 0x02 ], 0x12 );
                    x[ 0x03 ] ^= R( x[ 0x0F ] + x[ 0x0B ], 0x07 );
                    x[ 0x07 ] ^= R( x[ 0x03 ] + x[ 0x0F ], 0x09 );
                    x[ 0x0B ] ^= R( x[ 0x07 ] + x[ 0x03 ], 0x0D );
                    x[ 0x0F ] ^= R( x[ 0x0B ] + x[ 0x07 ], 0x12 );
                    x[ 0x01 ] ^= R( x[ 0x00 ] + x[ 0x03 ], 0x07 );
                    x[ 0x02 ] ^= R( x[ 0x01 ] + x[ 0x00 ], 0x09 );
                    x[ 0x03 ] ^= R( x[ 0x02 ] + x[ 0x01 ], 0x0D );
                    x[ 0x00 ] ^= R( x[ 0x03 ] + x[ 0x02 ], 0x12 );
                    x[ 0x06 ] ^= R( x[ 0x05 ] + x[ 0x04 ], 0x07 );
                    x[ 0x07 ] ^= R( x[ 0x06 ] + x[ 0x05 ], 0x09 );
                    x[ 0x04 ] ^= R( x[ 0x07 ] + x[ 0x06 ], 0x0D );
                    x[ 0x05 ] ^= R( x[ 0x04 ] + x[ 0x07 ], 0x12 );
                    x[ 0x0B ] ^= R( x[ 0x0A ] + x[ 0x09 ], 0x07 );
                    x[ 0x08 ] ^= R( x[ 0x0B ] + x[ 0x0A ], 0x09 );
                    x[ 0x09 ] ^= R( x[ 0x08 ] + x[ 0x0B ], 0x0D );
                    x[ 0x0A ] ^= R( x[ 0x09 ] + x[ 0x08 ], 0x12 );
                    x[ 0x0C ] ^= R( x[ 0x0F ] + x[ 0x0E ], 0x07 );
                    x[ 0x0D ] ^= R( x[ 0x0C ] + x[ 0x0F ], 0x09 );
                    x[ 0x0E ] ^= R( x[ 0x0D ] + x[ 0x0C ], 0x0D );
                    x[ 0x0F ] ^= R( x[ 0x0E ] + x[ 0x0D ], 0x12 );
                }

                for ( j = 0; j < 16; ++j )
                    _X[ j ] += x[ j ];

                /* Copy back the result. */
                for ( j = 0, k = Yi + ( i * 16 ); j < 16; j++ )
                    BY[ j + k ] = _X[ j ];
            }

            for ( i = 0; i < r; i++ ) {
                for ( j = 0, k = Yi + ( i * 2 ) * 16, l = ( i * 16 ); j < 16; j++ )
                    BY[ l + j ] = BY[ k + j ];
            }

            for ( i = 0; i < r; i++ ) {
                for ( j = 0, k = Yi + ( i * 2 + 1 ) * 16, l = ( i + r ) * 16; j < 16; j++ )
                    BY[ l + j ] = BY[ k + j ];
            }
        }

        /**
         * @desc Perform the scrypt process in steps and call the callback on intervals.
         * @param {string|Buffer|Array} input The input data to hash.
         * @param {string|Buffer|Array} salt The unique salt used for hashing.
         * @param {int} N The work factor variable. Memory and CPU usage scale linearly with this.
         * @param {int} r Increases the size of each hash produced by a factor of 2rK-bits.
         * @param {int} p Parallel factor. Indicates the number of mixing functions to be run simultaneously.
         * @param {ScryptCallback} cb Callback function for progress updates.
         * @private
         */
        function __perform( input, salt, N, r, p, cb ) {
            let totalOps, currentOps, lastPercentage;
            let b = PBKDF2_SHA256( input, salt, p * 128 * r, 1 );

            let B = new Uint32Array( p * 32 * r );

            let XY = new Uint32Array( 64 * r );
            let V = new Uint32Array( 32 * r * N );

            /* Salsa20 Scratchpad. */
            let x = new Uint32Array( 16 );
            /* Block-mix Salsa20 Scratchpad. */
            let _X = new Uint32Array( 16 );

            /* Initialize the input. */
            for ( let i = 0; i < B.length; i++ ) {
                let j = i * 4;
                B[ i ] =
                    ( ( b[ j + 3 ] & 0xff ) << 24 ) |
                    ( ( b[ j + 2 ] & 0xff ) << 16 ) |
                    ( ( b[ j + 1 ] & 0xff ) << 8 ) |
                    ( ( b[ j ] & 0xff ) << 0 );
            }

            let Yi = 32 * r;

            totalOps = p * N * 2;
            currentOps = 0;
            lastPercentage = null;

            /* Set this to true to abandon the scrypt on the next step. */
            let stop = false;

            /* State information. */
            let state = 0, stateCount = 0, i1;
            let Bi;

            /* How many block-mix salsa8 operations can we do per step? */
            let limit = parseInt( 1000 / r );

            /* Trick from scrypt-async; if there is a setImmediate shim in place, use it. */
            let nextTick = ( typeof( setImmediate ) !== 'undefined' ) ? setImmediate : setTimeout;

            const incrementalSMix = function () {
                if ( stop ) {
                    cb( new Error( 'cancelled' ), currentOps / totalOps );
                    return;
                }

                let steps, i, y, z, currentPercentage;
                switch ( state ) {
                case 0:
                    Bi = stateCount * 32 * r;
                    /* Row mix #1 */
                    for ( let z = 0; z < Yi; z++ )
                        XY[ z ] = B[ Bi + z ]

                    /* Move to second row mix. */
                    state = 1;
                    i1 = 0;
                /* Fall through purposely. */
                case 1:
                    /* Run up to 1000 steps of the first inner S-Mix loop. */
                    steps = N - i1;

                    if ( steps > limit )
                        steps = limit;

                    /* Row mix #2 */
                    for ( i = 0; i < steps; i++ ) {
                        /* Row mix #3 */
                        y = ( i1 + i ) * Yi;
                        z = Yi;
                        while ( z-- ) V[ z + y ] = XY[ z ];

                        /* Row mix #4 */
                        ScryptRowMix( XY, Yi, r, x, _X );
                    }

                    i1 += steps;
                    currentOps += steps;

                    /* Call the callback with the progress. ( Optionally stopping us. ) */
                    currentPercentage = parseInt( 1000 * currentOps / totalOps );
                    if ( currentPercentage !== lastPercentage ) {
                        stop = cb( null, currentOps / totalOps );

                        if ( stop )
                            break;

                        lastPercentage = currentPercentage;
                    }

                    if ( i1 < N )
                        break;

                    /* Row mix #6 */
                    i1 = 0;
                    state = 2;
                /* Fall through purposely. */
                case 2:

                    /* Run up to 1000 steps of the second inner S-Mix loop. */
                    steps = N - i1;

                    if ( steps > limit )
                        steps = limit;

                    for ( i = 0; i < steps; i++ ) {
                        /* Row mix #8 ( inner ) */
                        for ( z = 0, y = ( XY[ ( 2 * r - 1 ) * 16 ] & ( N - 1 ) ) * Yi; z < Yi; z++ )
                            XY[ z ] ^= V[ y + z ];
                        /* Row mix #9 ( outer ) */
                        ScryptRowMix( XY, Yi, r, x, _X );
                    }

                    i1 += steps;
                    currentOps += steps;

                    /* Call the callback with the progress. ( Optionally stopping us. ) */
                    currentPercentage = parseInt( 1000 * currentOps / totalOps );
                    if ( currentPercentage !== lastPercentage ) {
                        stop = cb( null, currentOps / totalOps );

                        if ( stop )
                            break;

                        lastPercentage = currentPercentage;
                    }

                    if ( i1 < N )
                        break;

                    /* Row mix #10 */
                    for ( z = 0; z < Yi; z++ )
                        B[ Bi + z ] = XY[ z ];

                    stateCount++;
                    if ( stateCount < p ) {
                        state = 0;
                        break;
                    }

                    b = [];
                    for ( i = 0; i < B.length; i++ ) {
                        b.push( ( B[ i ] >> 0 ) & 0xff );
                        b.push( ( B[ i ] >> 8 ) & 0xff );
                        b.push( ( B[ i ] >> 16 ) & 0xff );
                        b.push( ( B[ i ] >> 24 ) & 0xff );
                    }

                    /* Done. Don't break to avoid rescheduling. */
                    cb(
                        null,
                        1.0,
                        Buffer.from( PBKDF2_SHA256( input, Buffer.from( b ), output_length, 1 ) )
                    );
                    return;
                default:
                    cb( new Error( 'invalid state' ), 0 );
                    return;
                }

                /* Schedule the next steps. */
                nextTick( incrementalSMix );
            };

            incrementalSMix();
        }

        /* Validate input. */
        if ( typeof input === 'object' || typeof input === 'string' ) {
            if ( Array.isArray( input ) )
                _in = Buffer.from( input );
            else if ( Buffer.isBuffer( input ) )
                _in = input;
            else if ( typeof input === 'string' )
                _in = Buffer.from( input, 'utf8' );
            else {
                discordCrypt.log( 'Invalid input parameter type specified!', 'error' );
                return false;
            }
        }

        /* Validate salt. */
        if ( typeof salt === 'object' || typeof salt === 'string' ) {
            if ( Array.isArray( salt ) )
                _salt = Buffer.from( salt );
            else if ( Buffer.isBuffer( salt ) )
                _salt = salt;
            else if ( typeof salt === 'string' )
                _salt = Buffer.from( salt, 'utf8' );
            else {
                discordCrypt.log( 'Invalid salt parameter type specified!', 'error' );
                return false;
            }
        }

        /* Validate derived key length. */
        if ( typeof output_length !== 'number' ) {
            discordCrypt.log( 'Invalid output_length parameter specified. Must be a numeric value.', 'error' );
            return false;
        }
        else if ( output_length <= 0 || output_length >= 65536 ) {
            discordCrypt.log( 'Invalid output_length parameter specified. Must be a numeric value.', 'error' );
            return false;
        }

        /* Validate N is a power of 2. */
        if ( !N || N & ( N - 1 ) !== 0 ) {
            discordCrypt.log( 'Parameter N must be a power of 2.', 'error' );
            return false;
        }

        /* Perform a non-blocking . */
        if ( cb !== undefined && cb !== null ) {
            setTimeout( () => {
                __perform( _in, _salt, N, r, p, cb );
            }, 1 );
            return true;
        }

        /* Signal an error. */
        discordCrypt.log( 'No callback specified.', 'error' );
        return false;
    }

    /**
     * @public
     * @desc Returns the first 64 bits of a Whirlpool digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static whirlpool64( message, to_hex ) {
        return Buffer.from( discordCrypt.whirlpool( message, true ), 'hex' )
            .slice( 0, 8 ).toString( to_hex ? 'hex' : 'base64' );
    }

    /**
     * @public
     * @desc Returns the first 128 bits of an SHA-512 digest of a message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static sha512_128( message, to_hex ) {
        return Buffer.from( discordCrypt.sha512( message, true ), 'hex' )
            .slice( 0, 16 ).toString( to_hex ? 'hex' : 'base64' );
    }

    /**
     * @public
     * @desc Returns the first 192 bits of a Whirlpool digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static whirlpool192( message, to_hex ) {
        return Buffer.from( discordCrypt.sha512( message, true ), 'hex' )
            .slice( 0, 24 ).toString( to_hex ? 'hex' : 'base64' );
    }

    /**
     * @public
     * @desc Returns an SHA-160 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static sha160( message, to_hex ) {
        return discordCrypt.__createHash( message, 'sha1', to_hex );
    }

    /**
     * @public
     * @desc Returns an SHA-256 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static sha256( message, to_hex ) {
        return discordCrypt.__createHash( message, 'sha256', to_hex );
    }

    /**
     * @public
     * @desc Returns an SHA-512 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static sha512( message, to_hex ) {
        return discordCrypt.__createHash( message, 'sha512', to_hex );
    }

    /**
     * @public
     * @desc Returns a Whirlpool-512 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static whirlpool( message, to_hex ) {
        return discordCrypt.__createHash( message, 'whirlpool', to_hex );
    }

    /**
     * @public
     * @desc Returns a HMAC-SHA-256 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} secret The secret input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static hmac_sha256( message, secret, to_hex ) {
        return discordCrypt.__createHash( message, 'sha256', to_hex, true, secret );
    }

    /**
     * @public
     * @desc Returns an HMAC-SHA-512 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} secret The secret input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static hmac_sha512( message, secret, to_hex ) {
        return discordCrypt.__createHash( message, 'sha512', to_hex, true, secret );
    }

    /**
     * @public
     * @desc Returns an HMAC-Whirlpool-512 digest of the message.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} secret The secret input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @returns {string} Returns the hex or Base64 encoded result.
     */
    static hmac_whirlpool( message, secret, to_hex ) {
        return discordCrypt.__createHash( message, 'whirlpool', to_hex, true, secret );
    }

    /**
     * @public
     * @desc Computes a derived digest using the PBKDF2 algorithm and SHA-160 as primitives.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} salt The random salting input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @param {boolean} [message_is_hex] Whether to treat the message as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {boolean} [salt_is_hex] Whether to treat the salt as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {int} [key_length] The desired key length size in bytes. Default: 32.
     * @param {int} [iterations] The number of iterations to perform. Default: 5000.
     * @param {HashCallback} [callback] If defined, an async call is made that the result is passed to this when
     *      completed. If undefined, a sync call is made instead.
     * @returns {string|null} If a callback is defined, this returns nothing else it returns either a Base64 or hex
     *      encoded result.
     */
    static pbkdf2_sha160(
        message,
        salt,
        to_hex,
        message_is_hex = undefined,
        salt_is_hex = undefined,
        key_length = 32,
        iterations = 5000,
        callback = undefined
    ) {
        return discordCrypt.__pbkdf2(
            message,
            salt,
            to_hex,
            message_is_hex,
            salt_is_hex,
            callback,
            'sha1',
            key_length,
            iterations
        );
    }

    /**
     * @public
     * @desc Computes a derived digest using the PBKDF2 algorithm and SHA-256 as primitives.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} salt The random salting input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @param {boolean} [message_is_hex] Whether to treat the message as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {boolean} [salt_is_hex] Whether to treat the salt as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {int} [key_length] The desired key length size in bytes. Default: 32.
     * @param {int} [iterations] The number of iterations to perform. Default: 5000.
     * @param {HashCallback} [callback] If defined, an async call is made that the result is passed to this when
     *      completed. If undefined, a sync call is made instead.
     * @returns {string|null} If a callback is defined, this returns nothing else it returns either a Base64 or hex
     *      encoded result.
     */
    static pbkdf2_sha256(
        message,
        salt,
        to_hex,
        message_is_hex = undefined,
        salt_is_hex = undefined,
        key_length = 32,
        iterations = 5000,
        callback = undefined
    ) {
        return discordCrypt.__pbkdf2(
            message,
            salt,
            to_hex,
            message_is_hex,
            salt_is_hex,
            callback,
            'sha256',
            key_length,
            iterations
        );
    }

    /**
     * @public
     * @desc Computes a derived digest using the PBKDF2 algorithm and SHA-512 as primitives.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} salt The random salting input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @param {boolean} [message_is_hex] Whether to treat the message as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {boolean} [salt_is_hex] Whether to treat the salt as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {int} [key_length] The desired key length size in bytes. Default: 32.
     * @param {int} [iterations] The number of iterations to perform. Default: 5000.
     * @param {HashCallback} [callback] If defined, an async call is made that the result is passed to this when
     *      completed. If undefined, a sync call is made instead.
     * @returns {string|null} If a callback is defined, this returns nothing else it returns either a Base64 or hex
     *      encoded result.
     */
    static pbkdf2_sha512(
        /* Buffer|Array|string */   message,
        /* Buffer|Array|string */   salt,
        /* boolean */               to_hex,
        /* boolean */               message_is_hex = undefined,
        /* boolean */               salt_is_hex = undefined,
        /* int */                   key_length = 32,
        /* int */                   iterations = 5000,
        /* function(err, hash) */   callback = undefined
    ) {
        return discordCrypt.__pbkdf2(
            message,
            salt,
            to_hex,
            message_is_hex,
            salt_is_hex,
            callback,
            'sha512',
            key_length,
            iterations
        );
    }

    /**
     * @public
     * @desc Computes a derived digest using the PBKDF2 algorithm and Whirlpool-512 as primitives.
     * @param {Buffer|Array|string} message The input message to hash.
     * @param {Buffer|Array|string} salt The random salting input used with the message.
     * @param {boolean} to_hex Whether to convert the result to hex or Base64.
     * @param {boolean} [message_is_hex] Whether to treat the message as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {boolean} [salt_is_hex] Whether to treat the salt as a hex or Base64 string.
     *      If undefined, it is interpreted as a UTF-8 string.
     * @param {int} [key_length] The desired key length size in bytes. Default: 32.
     * @param {int} [iterations] The number of iterations to perform. Default: 5000.
     * @param {HashCallback} [callback] If defined, an async call is made that the result is passed to this when
     *      completed. If undefined, a sync call is made instead.
     * @returns {string|null} If a callback is defined, this returns nothing else it returns either a Base64 or hex
     *      encoded result.
     */
    static pbkdf2_whirlpool(
        message,
        salt,
        to_hex,
        message_is_hex = undefined,
        salt_is_hex = undefined,
        key_length = 32,
        iterations = 5000,
        callback = undefined
    ) {
        return discordCrypt.__pbkdf2(
            message,
            salt,
            to_hex,
            message_is_hex,
            salt_is_hex,
            callback,
            'whirlpool',
            key_length,
            iterations
        );
    }

    /**
     * @public
     * @desc Encrypts the given plain-text message using the algorithm specified.
     * @param {string} symmetric_cipher The name of the symmetric cipher used to encrypt the message.
     *      This must be supported by NodeJS's crypto module.
     * @param {string} block_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_scheme The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {boolean} convert_to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [key_size_bits] The size of the input key required for the chosen cipher. Defaults to 256 bits.
     * @param {int} [block_cipher_size] The size block cipher in bits. Defaults to 128 bits.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer|null} Returns a Buffer() object containing the ciphertext or null if the chosen options are
     *      invalid.
     * @throws Exception indicating the error that occurred.
     */
    static __encrypt(
        symmetric_cipher,
        block_mode,
        padding_scheme,
        message,
        key,
        convert_to_hex,
        is_message_hex,
        key_size_bits = 256,
        block_cipher_size = 128,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        const cipher_name = `${symmetric_cipher}${block_mode === undefined ? '' : '-' + block_mode}`;
        const crypto = require( 'crypto' );

        /* Buffered parameters. */
        let _message, _key, _iv, _salt, _derived, _encrypt;

        /* Make sure the cipher name and mode is valid first. */
        if (
            !discordCrypt.__isValidCipher( cipher_name ) || [ 'cbc', 'cfb', 'ofb' ]
                .indexOf( block_mode.toLowerCase() ) === -1
        )
            return null;

        /* Pad the message to the nearest block boundary. */
        _message = discordCrypt.__padMessage( message, padding_scheme, key_size_bits, is_message_hex );

        /* Get the key as a buffer. */
        _key = discordCrypt.__validateKeyIV( key, key_size_bits );

        /* Check if using a predefined salt. */
        if ( one_time_salt !== undefined ) {
            /* Convert the salt to a Buffer. */
            _salt = discordCrypt.__toBuffer( one_time_salt );

            /* Don't bother continuing if conversions have failed. */
            if ( !_salt || _salt.length === 0 )
                return null;

            /* Only 64 bits is used for a salt. If it's not that length, hash it and use the result. */
            if ( _salt.length !== 8 )
                _salt = Buffer.from( discordCrypt.whirlpool64( _salt, true ), 'hex' );
        }
        else {
            /* Generate a random salt to derive the key and IV. */
            _salt = crypto.randomBytes( 8 );
        }

        /* Derive the key length and IV length. */
        _derived = discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), kdf_iteration_rounds );

        /* Slice off the IV. */
        _iv = _derived.slice( 0, block_cipher_size / 8 );

        /* Slice off the key. */
        _key = _derived.slice( block_cipher_size / 8, ( block_cipher_size / 8 ) + ( key_size_bits / 8 ) );

        /* Create the cipher with derived IV and key. */
        _encrypt = crypto.createCipheriv( cipher_name, _key, _iv );

        /* Disable automatic PKCS #7 padding. We do this in-house. */
        _encrypt.setAutoPadding( false );

        /* Get the cipher text. */
        let _ct = _encrypt.update( _message, undefined, 'hex' );
        _ct += _encrypt.final( 'hex' );

        /* Return the result with the prepended salt. */
        return Buffer.from( _salt.toString( 'hex' ) + _ct, 'hex' ).toString( convert_to_hex ? 'hex' : 'base64' );
    }

    /**
     * @public
     * @desc Decrypts the given cipher-text message using the algorithm specified.
     * @param {string} symmetric_cipher The name of the symmetric cipher used to decrypt the message.
     *      This must be supported by NodeJS's crypto module.
     * @param {string} block_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_scheme The padding scheme used to unpad the message from the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string|Buffer|Array} message The input ciphertext message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {boolean} output_format The output format of the plaintext.
     *      Can be either [ 'utf8', 'latin1', 'hex', 'base64' ]
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [key_size_bits] The size of the input key required for the chosen cipher. Defaults to 256 bits.
     * @param {int} [block_cipher_size] The size block cipher in bits. Defaults to 128 bits.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     * options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static __decrypt(
        symmetric_cipher,
        block_mode,
        padding_scheme,
        message,
        key,
        output_format,
        is_message_hex,
        key_size_bits = 256,
        block_cipher_size = 128,
        kdf_iteration_rounds = 1000
    ) {
        const cipher_name = `${symmetric_cipher}${block_mode === undefined ? '' : '-' + block_mode}`;
        const crypto = require( 'crypto' );

        /* Buffered parameters. */
        let _message, _key, _iv, _salt, _derived, _decrypt;

        /* Make sure the cipher name and mode is valid first. */
        if ( !discordCrypt.__isValidCipher( cipher_name ) || [ 'cbc', 'ofb', 'cfb' ]
            .indexOf( block_mode.toLowerCase() ) === -1 )
            return null;

        /* Get the message as a buffer. */
        _message = discordCrypt.__validateMessage( message, is_message_hex );

        /* Get the key as a buffer. */
        _key = discordCrypt.__validateKeyIV( key, key_size_bits );

        /* Retrieve the 64-bit salt. */
        _salt = _message.slice( 0, 8 );

        /* Derive the key length and IV length. */
        _derived = discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), kdf_iteration_rounds );

        /* Slice off the IV. */
        _iv = _derived.slice( 0, block_cipher_size / 8 );

        /* Slice off the key. */
        _key = _derived.slice( block_cipher_size / 8, ( block_cipher_size / 8 ) + ( key_size_bits / 8 ) );

        /* Splice the message. */
        _message = _message.slice( 8 );

        /* Create the cipher with IV. */
        _decrypt = crypto.createDecipheriv( cipher_name, _key, _iv );

        /* Disable automatic PKCS #7 padding. We do this in-house. */
        _decrypt.setAutoPadding( false );

        /* Decrypt the cipher text. */
        let _pt = _decrypt.update( _message, undefined, 'hex' );
        _pt += _decrypt.final( 'hex' );

        /* Unpad the message. */
        _pt = discordCrypt.__padMessage( _pt, padding_scheme, key_size_bits, true, true );

        /* Return the buffer. */
        return _pt.toString( output_format );
    }


    /**
     * @public
     * @desc Blowfish encrypts a message.
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {boolean} to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer} Returns a Buffer() object containing the resulting ciphertext.
     * @throws An exception indicating the error that occurred.
     */
    static blowfish512_encrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        to_hex = false,
        is_message_hex = undefined,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for Blowfish. */
        const keySize = 512, blockSize = 64;

        /* Perform the encryption. */
        return discordCrypt.__encrypt(
            'bf',
            cipher_mode,
            padding_mode,
            message,
            key,
            to_hex,
            is_message_hex,
            keySize,
            blockSize,
            one_time_salt,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc Blowfish decrypts a message.
     * @param {string|Buffer|Array} message The input message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string} output_format The output format of the decrypted message.
     *      This can be either: [ 'hex', 'base64', 'latin1', 'utf8' ].
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     *      options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static blowfish512_decrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        output_format = 'utf8',
        is_message_hex = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for Blowfish. */
        const keySize = 512, blockSize = 64;

        /* Return the unpadded message. */
        return discordCrypt.__decrypt(
            'bf',
            cipher_mode,
            padding_mode,
            message,
            key,
            output_format,
            is_message_hex,
            keySize,
            blockSize,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc AES-256 encrypts a message.
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {boolean} to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer} Returns a Buffer() object containing the resulting ciphertext.
     * @throws An exception indicating the error that occurred.
     */
    static aes256_encrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        to_hex = false,
        is_message_hex = undefined,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for AES-256. */
        const keySize = 256, blockSize = 128;

        /* Perform the encryption. */
        return discordCrypt.__encrypt(
            'aes-256',
            cipher_mode,
            padding_mode,
            message,
            key,
            to_hex,
            is_message_hex,
            keySize,
            blockSize,
            one_time_salt,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc AES-256 decrypts a message.
     * @param {string|Buffer|Array} message The input message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string} output_format The output format of the decrypted message.
     *      This can be either: [ 'hex', 'base64', 'latin1', 'utf8' ].
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     *      options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static aes256_decrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        output_format = 'utf8',
        is_message_hex = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for AES-256. */
        const keySize = 256, blockSize = 128;

        /* Return the unpadded message. */
        return discordCrypt.__decrypt(
            'aes-256',
            cipher_mode,
            padding_mode,
            message,
            key,
            output_format,
            is_message_hex,
            keySize,
            blockSize,
            kdf_iteration_rounds
        );
    }

    /*  */
    /**
     * @public
     * @desc AES-256 decrypts a message in GCM mode.
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {boolean} to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [additional_data] If specified, this additional data is used during GCM
     *      authentication.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer} Returns a Buffer() object containing the resulting ciphertext.
     * @throws An exception indicating the error that occurred.
     */
    static aes256_encrypt_gcm(
        message,
        key,
        padding_mode,
        to_hex = false,
        is_message_hex = undefined,
        additional_data = undefined,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        const block_cipher_size = 128, key_size_bits = 256;
        const cipher_name = 'aes-256-gcm';
        const crypto = require( 'crypto' );

        let _message, _key, _iv, _salt, _derived, _encrypt;

        /* Pad the message to the nearest block boundary. */
        _message = discordCrypt.__padMessage( message, padding_mode, key_size_bits, is_message_hex );

        /* Get the key as a buffer. */
        _key = discordCrypt.__validateKeyIV( key, key_size_bits );

        /* Check if using a predefined salt. */
        if ( one_time_salt !== undefined ) {
            /* Convert the salt to a Buffer. */
            _salt = discordCrypt.__toBuffer( one_time_salt );

            /* Don't bother continuing if conversions have failed. */
            if ( !_salt || _salt.length === 0 )
                return null;

            /* Only 64 bits is used for a salt. If it's not that length, hash it and use the result. */
            if ( _salt.length !== 8 )
                _salt = Buffer.from( discordCrypt.whirlpool64( _salt, true ), 'hex' );
        }
        else {
            /* Generate a random salt to derive the key and IV. */
            _salt = crypto.randomBytes( 8 );
        }

        /* Derive the key length and IV length. */
        _derived = discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), kdf_iteration_rounds );

        /* Slice off the IV. */
        _iv = _derived.slice( 0, block_cipher_size / 8 );

        /* Slice off the key. */
        _key = _derived.slice( block_cipher_size / 8, ( block_cipher_size / 8 ) + ( key_size_bits / 8 ) );

        /* Create the cipher with derived IV and key. */
        _encrypt = crypto.createCipheriv( cipher_name, _key, _iv );

        /* Add the additional data if necessary. */
        if ( additional_data !== undefined )
            _encrypt.setAAD( discordCrypt.__toBuffer( additional_data ) );

        /* Disable automatic PKCS #7 padding. We do this in-house. */
        _encrypt.setAutoPadding( false );

        /* Get the cipher text. */
        let _ct = _encrypt.update( _message, undefined, 'hex' );
        _ct += _encrypt.final( 'hex' );

        /* Return the auth tag prepended with the salt to the message. */
        return Buffer.from(
            _encrypt.getAuthTag().toString( 'hex' ) + _salt.toString( 'hex' ) + _ct,
            'hex'
        ).toString( to_hex ? 'hex' : 'base64' );
    }

    /**
     * @public
     * @desc AES-256 decrypts a message in GCM mode.
     * @param {string|Buffer|Array} message The input message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string} output_format The output format of the decrypted message.
     *      This can be either: [ 'hex', 'base64', 'latin1', 'utf8' ].
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [additional_data] If specified, this additional data is used during GCM
     *      authentication.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     *      options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static aes256_decrypt_gcm(
        message,
        key,
        padding_mode,
        output_format = 'utf8',
        is_message_hex = undefined,
        additional_data = undefined,
        kdf_iteration_rounds = 1000
    ) {
        const block_cipher_size = 128, key_size_bits = 256;
        const cipher_name = 'aes-256-gcm';
        const crypto = require( 'crypto' );

        /* Buffered parameters. */
        let _message, _key, _iv, _salt, _authTag, _derived, _decrypt;

        /* Get the message as a buffer. */
        _message = discordCrypt.__validateMessage( message, is_message_hex );

        /* Get the key as a buffer. */
        _key = discordCrypt.__validateKeyIV( key, key_size_bits );

        /* Retrieve the auth tag. */
        _authTag = _message.slice( 0, block_cipher_size / 8 );

        /* Splice the message. */
        _message = _message.slice( block_cipher_size / 8 );

        /* Retrieve the 64-bit salt. */
        _salt = _message.slice( 0, 8 );

        /* Splice the message. */
        _message = _message.slice( 8 );

        /* Derive the key length and IV length. */
        _derived = discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), kdf_iteration_rounds );

        /* Slice off the IV. */
        _iv = _derived.slice( 0, block_cipher_size / 8 );

        /* Slice off the key. */
        _key = _derived.slice( block_cipher_size / 8, ( block_cipher_size / 8 ) + ( key_size_bits / 8 ) );

        /* Create the cipher with IV. */
        _decrypt = crypto.createDecipheriv( cipher_name, _key, _iv );

        /* Set the authentication tag. */
        _decrypt.setAuthTag( _authTag );

        /* Set the additional data for verification if necessary. */
        if ( additional_data !== undefined )
            _decrypt.setAAD( discordCrypt.__toBuffer( additional_data ) );

        /* Disable automatic PKCS #7 padding. We do this in-house. */
        _decrypt.setAutoPadding( false );

        /* Decrypt the cipher text. */
        let _pt = _decrypt.update( _message, undefined, 'hex' );
        _pt += _decrypt.final( 'hex' );

        /* Unpad the message. */
        _pt = discordCrypt.__padMessage( _pt, padding_mode, key_size_bits, true, true );

        /* Return the buffer. */
        return _pt.toString( output_format );
    }

    /**
     * @public
     * @desc Camellia-256 encrypts a message.
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {boolean} to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer} Returns a Buffer() object containing the resulting ciphertext.
     * @throws An exception indicating the error that occurred.
     */
    static camellia256_encrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        to_hex = false,
        is_message_hex = undefined,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for Camellia-256. */
        const keySize = 256, blockSize = 128;

        /* Perform the encryption. */
        return discordCrypt.__encrypt(
            'camellia-256',
            cipher_mode,
            padding_mode,
            message,
            key,
            to_hex,
            is_message_hex,
            keySize,
            blockSize,
            one_time_salt,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc Camellia-256 decrypts a message.
     * @param {string|Buffer|Array} message The input message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string} output_format The output format of the decrypted message.
     *      This can be either: [ 'hex', 'base64', 'latin1', 'utf8' ].
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     *      options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static camellia256_decrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        output_format = 'utf8',
        is_message_hex = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for Camellia-256. */
        const keySize = 256, blockSize = 128;

        /* Return the unpadded message. */
        return discordCrypt.__decrypt(
            'camellia-256',
            cipher_mode,
            padding_mode,
            message,
            key,
            output_format,
            is_message_hex,
            keySize,
            blockSize,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc TripleDES-192 encrypts a message.
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {boolean} to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer} Returns a Buffer() object containing the resulting ciphertext.
     * @throws An exception indicating the error that occurred.
     */
    static tripledes192_encrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        to_hex = false,
        is_message_hex = undefined,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for TripleDES-192. */
        const keySize = 192, blockSize = 64;

        /* Perform the encryption. */
        return discordCrypt.__encrypt(
            'des-ede3',
            cipher_mode,
            padding_mode,
            message,
            key,
            to_hex,
            is_message_hex,
            keySize,
            blockSize,
            one_time_salt,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc TripleDES-192 decrypts a message.
     * @param {string|Buffer|Array} message The input message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string} output_format The output format of the decrypted message.
     *      This can be either: [ 'hex', 'base64', 'latin1', 'utf8' ].
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     *      options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static tripledes192_decrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        output_format = 'utf8',
        is_message_hex = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for TripleDES-192. */
        const keySize = 192, blockSize = 64;

        /* Return the unpadded message. */
        return discordCrypt.__decrypt(
            'des-ede3',
            cipher_mode,
            padding_mode,
            message,
            key,
            output_format,
            is_message_hex,
            keySize,
            blockSize,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc IDEA-128 encrypts a message.
     * @param {string|Buffer|Array} message The input message to encrypt.
     * @param {string|Buffer|Array} key The key used with the encryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {boolean} to_hex If true, the ciphertext is converted to a hex string, if false, it is
     *      converted to a Base64 string.
     * @param {boolean} is_message_hex If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {string|Buffer|Array} [one_time_salt] If specified, contains the 64-bit salt used to derive an IV and
     *      Key used to encrypt the message.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {Buffer} Returns a Buffer() object containing the resulting ciphertext.
     * @throws An exception indicating the error that occurred.
     */
    static idea128_encrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        to_hex = false,
        is_message_hex = undefined,
        one_time_salt = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for IDEA-128. */
        const keySize = 128, blockSize = 64;

        /* Perform the encryption. */
        return discordCrypt.__encrypt(
            'idea',
            cipher_mode,
            padding_mode,
            message,
            key,
            to_hex,
            is_message_hex,
            keySize,
            blockSize,
            one_time_salt,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc IDEA-128 decrypts a message.
     * @param {string|Buffer|Array} message The input message to decrypt.
     * @param {string|Buffer|Array} key The key used with the decryption cipher.
     * @param {string} cipher_mode The block operation mode of the cipher.
     *      This can be either [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     * @param {string} output_format The output format of the decrypted message.
     *      This can be either: [ 'hex', 'base64', 'latin1', 'utf8' ].
     * @param {boolean} [is_message_hex] If true, the message is treated as a hex string, if false, it is treated as
     *      a Base64 string. If undefined, the message is treated as a UTF-8 string.
     * @param {int} [kdf_iteration_rounds] The number of rounds used to derive the actual key and IV via sha256.
     * @returns {string|null} Returns a string of the desired format containing the plaintext or null if the chosen
     *      options are invalid.
     * @throws Exception indicating the error that occurred.
     */
    static idea128_decrypt(
        message,
        key,
        cipher_mode,
        padding_mode,
        output_format = 'utf8',
        is_message_hex = undefined,
        kdf_iteration_rounds = 1000
    ) {
        /* Size constants for IDEA-128. */
        const keySize = 128, blockSize = 64;

        /* Return the unpadded message. */
        return discordCrypt.__decrypt(
            'idea',
            cipher_mode,
            padding_mode,
            message,
            key,
            output_format,
            is_message_hex,
            keySize,
            blockSize,
            kdf_iteration_rounds
        );
    }

    /**
     * @public
     * @desc Converts a cipher string to its appropriate index number.
     * @param {string} primary_cipher The primary cipher.
     *      This can be either [ 'bf', 'aes', 'camel', 'idea', 'tdes' ].
     * @param {string} [secondary_cipher] The secondary cipher.
     *      This can be either [ 'bf', 'aes', 'camel', 'idea', 'tdes' ].
     * @returns {int} Returns the index value of the algorithm.
     */
    static cipherStringToIndex( primary_cipher, secondary_cipher = undefined ) {
        let value = 0;

        /* Return if already a number. */
        if ( typeof primary_cipher === 'number' )
            return primary_cipher;

        /* Check if it's a joined string. */
        if ( typeof primary_cipher === 'string' && primary_cipher.search( '-' ) !== -1 &&
            secondary_cipher === undefined ) {
            primary_cipher = primary_cipher.split( '-' )[ 0 ];
            secondary_cipher = primary_cipher.split( '-' )[ 1 ];
        }

        /* Resolve the primary index. */
        switch ( primary_cipher ) {
        case 'bf':
            /* value = 0; */
            break;
        case 'aes':
            value = 1;
            break;
        case 'camel':
            value = 2;
            break;
        case 'idea':
            value = 3;
            break;
        case 'tdes':
            value = 4;
            break;
        default:
            return 0;
        }

        /* Make sure the secondary is valid. */
        if ( secondary_cipher !== undefined ) {
            switch ( secondary_cipher ) {
            case 'bf':
                /* value = 0; */
                break;
            case 'aes':
                value += 5;
                break;
            case 'camel':
                value += 10;
                break;
            case 'idea':
                value += 15;
                break;
            case 'tdes':
                value += 20;
                break;
            default:
                break;
            }
        }

        /* Return the index. */
        return value;
    }

    /**
     * @public
     * @desc Converts an algorithm index to its appropriate string value.
     * @param {int} index The index of the cipher(s) used.
     * @param {boolean} get_secondary Whether to retrieve the secondary algorithm name.
     * @returns {string} Returns a shorthand representation of either the primary or secondary cipher.
     *      This can be either [ 'bf', 'aes', 'camel', 'idea', 'tdes' ].
     */
    static cipherIndexToString( index, get_secondary = undefined ) {

        /* Strip off the secondary. */
        if ( get_secondary !== undefined && get_secondary ) {
            if ( index >= 20 )
                return 'tdes';
            else if ( index >= 15 )
                return 'idea';
            else if ( index >= 10 )
                return 'camel';
            else if ( index >= 5 )
                return 'aes';
            else
                return 'bf';
        }
        /* Remove the secondary. */
        else if ( index >= 20 )
            index -= 20;
        else if ( index >= 15 && index <= 19 )
            index -= 15;
        else if ( index >= 10 && index <= 14 )
            index -= 10;
        else if ( index >= 5 && index <= 9 )
            index -= 5;

        /* Calculate the primary. */
        if ( index === 1 )
            return 'aes';
        else if ( index === 2 )
            return 'camel';
        else if ( index === 3 )
            return 'idea';
        else if ( index === 4 )
            return 'tdes';
        else
            return 'bf';
    }

    /**
     * @public
     * @desc Converts an input string to the approximate entropic bits using Shannon's algorithm.
     * @param {string} key The input key to check.
     * @returns {int} Returns the approximate number of bits of entropy contained in the key.
     */
    static entropicBitLength( key ) {
        let h = Object.create( null ), k;
        let sum = 0, len = key.length;

        key.split( '' ).forEach( c => {
            h[ c ] ? h[ c ]++ : h[ c ] = 1;
        } );

        for ( k in h ) {
            let p = h[ k ] / len;
            sum -= p * Math.log( p ) / Math.log( 2 );
        }

        return parseInt( sum * len );
    }

    /**
     * @public
     * @desc Returns 256-characters of Braille.
     * @return {string}
     */
    static getBraille() {
        return Array.from(
            "⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿⡀⡁⡂⡃⡄⡅⡆⡇⡈⡉⡊⡋⡌⡍⡎⡏⡐⡑⡒⡓⡔⡕⡖" +
            "⡗⡘⡙⡚⡛⡜⡝⡞⡟⡠⡡⡢⡣⡤⡥⡦⡧⡨⡩⡪⡫⡬⡭⡮⡯⡰⡱⡲⡳⡴⡵⡶⡷⡸⡹⡺⡻⡼⡽⡾⡿⢀⢁⢂⢃⢄⢅⢆⢇⢈⢉⢊⢋⢌⢍⢎⢏⢐⢑⢒⢓⢔⢕⢖⢗⢘⢙⢚⢛⢜⢝⢞⢟⢠⢡⢢⢣⢤⢥⢦⢧⢨⢩⢪⢫⢬⢭" +
            "⢮⢯⢰⢱⢲⢳⢴⢵⢶⢷⢸⢹⢺⢻⢼⢽⢾⢿⣀⣁⣂⣃⣄⣅⣆⣇⣈⣉⣊⣋⣌⣍⣎⣏⣐⣑⣒⣓⣔⣕⣖⣗⣘⣙⣚⣛⣜⣝⣞⣟⣠⣡⣢⣣⣤⣥⣦⣧⣨⣩⣪⣫⣬⣭⣮⣯⣰⣱⣲⣳⣴⣵⣶⣷⣸⣹⣺⣻⣼⣽⣾⣿"
        );
    }

    /**
     * @public
     * @desc Determines if a string has all valid Braille characters according to the result from getBraille()
     * @param {string} message The message to validate.
     * @returns {boolean} Returns true if the message contains only the required character set.
     */
    static isValidBraille( message ) {
        let c = discordCrypt.getBraille();

        for ( let i = 0; i < message.length; i++ )
            if ( c.indexOf( message[ i ] ) === -1 )
                return false;

        return true;
    }

    /**
     * @public
     * @desc Retrieves Base64 charset as an Array Object.
     * @returns {Array} Returns an array of all 64 characters used in Base64 + encoding characters.
     */
    static getBase64() {
        return Array.from( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" );
    }

    /**
     * @public
     * @desc Returns an array of valid Diffie-Hellman exchange key bit-sizes.
     * @returns {number[]} Returns the bit lengths of all supported DH keys.
     */
    static getDHBitSizes() {
        return [ 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192 ];
    }

    /**
     * @public
     * @desc Returns an array of Elliptic-Curve Diffie-Hellman key bit-sizes.
     * @returns {number[]} Returns the bit lengths of all supported ECDH keys.
     */
    static getECDHBitSizes() {
        return [ 224, 256, 384, 409, 521, 571 ];
    }

    /**
     * @public
     * @desc Determines if a key exchange algorithm's index is valid.
     * @param {int} index The index to determine if valid.
     * @returns {boolean} Returns true if the desired index meets one of the ECDH or DH key sizes.
     */
    static isValidExchangeAlgorithm( index ) {
        return index >= 0 &&
            index <= ( discordCrypt.getDHBitSizes().length + discordCrypt.getECDHBitSizes().length - 1 );
    }

    /**
     * @public
     * @desc Converts an algorithm index to a string.
     * @param {int} index The input index of the exchange algorithm.
     * @returns {string} Returns a string containing the algorithm or "Invalid Algorithm".
     */
    static indexToExchangeAlgorithmString( index ) {
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();
        let base = [ 'DH-', 'ECDH-' ];

        if ( !discordCrypt.isValidExchangeAlgorithm( index ) )
            return 'Invalid Algorithm';

        return ( index <= ( dh_bl.length - 1 ) ?
            base[ 0 ] + dh_bl[ index ] :
            base[ 1 ] + ecdh_bl[ index - dh_bl.length ] );
    }

    /**
     * @public
     * @desc Converts an algorithm index to a bit size.
     * @param {int} index The index to convert to the bit length.
     * @returns {int} Returns 0 if the index is invalid or the bit length of the index.
     */
    static indexToAlgorithmBitLength( index ) {
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();

        if ( !discordCrypt.isValidExchangeAlgorithm( index ) )
            return 0;

        return ( index <= ( dh_bl.length - 1 ) ? dh_bl[ index ] : ecdh_bl[ index - dh_bl.length ] );
    }

    /**
     * @public
     * @desc Computes a secret key from two ECDH or DH keys. One private and one public.
     * @param {Object} private_key A private key DH or ECDH object from NodeJS's crypto module.
     * @param {string} public_key The public key as a string in Base64 or hex format.
     * @param {boolean} is_base_64 Whether the public key is a Base64 string. If false, it is assumed to be hex.
     * @param {boolean} to_base_64 Whether to convert the output secret to Base64.
     *      If false, it is converted to hex.
     * @returns {string|null} Returns a string encoded secret on success or null on failure.
     */
    static computeExchangeSharedSecret( private_key, public_key, is_base_64, to_base_64 ) {
        let in_form, out_form;

        /* Compute the formats. */
        in_form = is_base_64 ? 'base64' : 'hex';
        out_form = to_base_64 ? 'base64' : 'hex';

        /* Compute the derived key and return. */
        try {
            return private_key.computeSecret( public_key, in_form, out_form );
        }
        catch ( e ) {
            return null;
        }
    }

    /**
     * @public
     * @desc Generates a Diffie-Hellman key pair.
     * @param {int} size The bit length of the desired key pair.
     *      This must be one of the supported lengths retrieved from getDHBitSizes().
     * @param {Buffer} private_key The optional private key used to initialize the object.
     * @returns {Object|null} Returns a DiffieHellman object on success or null on failure.
     */
    static generateDH( size, private_key = undefined ) {
        let groupName, key;

        /* Calculate the appropriate group. */
        switch ( size ) {
        case 768:
            groupName = 'modp1';
            break;
        case 1024:
            groupName = 'modp2';
            break;
        case 1536:
            groupName = 'modp5';
            break;
        case 2048:
            groupName = 'modp14';
            break;
        case 3072:
            groupName = 'modp15';
            break;
        case 4096:
            groupName = 'modp16';
            break;
        case 6144:
            groupName = 'modp17';
            break;
        case 8192:
            groupName = 'modp18';
            break;
        default:
            return null;
        }

        /* Create the key object. */
        try {
            key = require( 'crypto' ).getDiffieHellman( groupName );
        }
        catch ( err ) {
            return null;
        }

        /* Generate the key if it's valid. */
        if ( key !== undefined && key !== null && typeof key.generateKeys !== 'undefined' ) {
            if ( private_key === undefined )
                key.generateKeys();
            else if ( typeof key.setPrivateKey !== 'undefined' )
                key.setPrivateKey( private_key );
        }

        /* Return the result. */
        return key;
    }

    /**
     * @public
     * @see http://www.secg.org/sec2-v2.pdf
     * @desc Generates a Elliptic-Curve Diffie-Hellman key pair.
     * @param {int} size The bit length of the desired key pair.
     *      This must be one of the supported lengths retrieved from getECDHBitSizes().
     * @param {Buffer} private_key The optional private key used to initialize the object.
     * @returns {Object|null} Returns a ECDH object on success or null on failure.
     */
    static generateECDH( size, private_key = undefined ) {
        let groupName, key;

        /* Calculate the appropriate group. */
        switch ( size ) {
        case 224:
            groupName = 'secp224k1';
            break;
        case 384:
            groupName = 'secp384r1';
            break;
        case 409:
            groupName = 'sect409k1';
            break;
        case 521:
            groupName = 'secp521r1';
            break;
        case 571:
            groupName = 'sect571k1';
            break;
        case 256:
            break;
        default:
            return null;
        }

        /* Create the key object. */
        try {
            if ( size !== 256 )
                key = require( 'crypto' ).createECDH( groupName );
            else {
                key = new global.Curve25519();
                key.generateKeys( undefined, require( 'crypto' ).randomBytes( 32 ) );
            }
        }
        catch ( err ) {
            return null;
        }

        /* Generate the key if it's valid. */
        if ( key !== undefined && key !== null && typeof key.generateKeys !== 'undefined' && size !== 256 ) {
            /* Generate a new key if the private key is undefined else set the private key. */
            if ( private_key === undefined )
                key.generateKeys( 'hex', 'compressed' );
            else if ( typeof key.setPrivateKey !== 'undefined' )
                key.setPrivateKey( private_key );
        }

        /* Return the result. */
        return key;
    }

    /**
     * @public
     * @desc Substitutes an input Buffer() object to the Braille equivalent from getBraille().
     * @param {string} message The input message to perform substitution on.
     * @param {boolean} convert Whether the message is to be converted from hex to Braille or from Braille to hex.
     * @returns {string} Returns the substituted string encoded message.
     * @throws An exception indicating the message contains characters not in the character set.
     */
    static substituteMessage( message, convert ) {
        /* Target character set. */
        let subset = discordCrypt.getBraille();

        let result = "", index = 0;

        if ( convert !== undefined ) {
            /* Sanity check. */
            if ( !Buffer.isBuffer( message ) )
                throw 'Message input is not a buffer.';

            /* Calculate the target character. */
            for ( let i = 0; i < message.length; i++ )
                result += subset[ message[ i ] ];
        }
        else {
            /* Calculate the target character. */
            for ( let i = 0; i < message.length; i++ ) {
                index = subset.indexOf( message[ i ] );

                /* Sanity check. */
                if ( index === -1 )
                    throw 'Message contains invalid characters.';

                result += `0${index.toString( 16 )}`.slice( -2 );
            }
        }

        return result;
    }

    /**
     * @public
     * @desc Encodes the given values as a braille encoded 32-bit word.
     * @param {int} cipher_index The index of the cipher(s) used to encrypt the message
     * @param {int} cipher_mode_index The index of the cipher block mode used for the message.
     * @param {int} padding_scheme_index The index of the padding scheme for the message.
     * @param {int} pad_byte The padding byte to use.
     * @returns {string} Returns a substituted UTF-16 string of a braille encoded 32-bit word containing these options.
     */
    static metaDataEncode( cipher_index, cipher_mode_index, padding_scheme_index, pad_byte ) {

        /* Parse the first 8 bits. */
        if ( typeof cipher_index === 'string' )
            cipher_index = discordCrypt.cipherStringToIndex( cipher_index );

        /* Parse the next 8 bits. */
        if ( typeof cipher_mode_index === 'string' )
            cipher_mode_index = [ 'cbc', 'cfb', 'ofb' ].indexOf( cipher_mode_index.toLowerCase() );

        /* Parse the next 8 bits. */
        if ( typeof padding_scheme_index === 'string' )
            padding_scheme_index = [ 'pkc7', 'ans2', 'iso1', 'iso9' ].indexOf( padding_scheme_index.toLowerCase() );

        /* Buffered word. */
        let buf = Buffer.from( [ cipher_index, cipher_mode_index, padding_scheme_index, parseInt( pad_byte ) ] );

        /* Convert it and return. */
        return discordCrypt.substituteMessage( buf, true );
    }

    /**
     * @public
     * @desc Decodes an input string and returns a byte array containing index number of options.
     * @param {string} message The substituted UTF-16 encoded metadata containing the metadata options.
     * @returns {int[]} Returns 4 integer indexes of each metadata value.
     */
    static metaDataDecode( message ) {
        /* Decode the result and convert the hex to a Buffer. */
        return Buffer.from( discordCrypt.substituteMessage( message ), 'hex' );
    }

    /**
     * @public
     * @desc Dual-encrypts a message using symmetric keys and returns the substituted encoded equivalent.
     * @param {string|Buffer} message The input message to encrypt.
     * @param {Buffer} primary_key The primary key used for the first level of encryption.
     * @param {Buffer} secondary_key The secondary key used for the second level of encryption.
     * @param {int} cipher_index The cipher index containing the primary and secondary ciphers used for encryption.
     * @param {string} block_mode The block operation mode of the ciphers.
     *      These can be: [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     *      This prepends a 64 bit seed used to derive encryption keys from the initial key.
     * @returns {string|null} Returns the encrypted and substituted ciphertext of the message or null on failure.
     * @throws An exception indicating the error that occurred.
     */
    static symmetricEncrypt( message, primary_key, secondary_key, cipher_index, block_mode, padding_mode ) {
        const customizationParameter = new Uint8Array( Buffer.from( 'DiscordCrypt MAC' ) );

        /* Performs one of the 5 standard encryption algorithms on the plain text. */
        function handleEncodeSegment( message, key, cipher, mode, pad ) {
            switch ( cipher ) {
            case 0:
                return discordCrypt.blowfish512_encrypt( message, key, mode, pad );
            case 1:
                return discordCrypt.aes256_encrypt( message, key, mode, pad );
            case 2:
                return discordCrypt.camellia256_encrypt( message, key, mode, pad );
            case 3:
                return discordCrypt.idea128_encrypt( message, key, mode, pad );
            case 4:
                return discordCrypt.tripledes192_encrypt( message, key, mode, pad );
            default:
                return null;
            }
        }

        /* Convert the block mode. */
        let mode = block_mode.toLowerCase();

        /* Convert the padding. */
        let pad = padding_mode;

        /* Encode using the user-specified symmetric algorithm. */
        let msg = '';

        /* Dual-encrypt the segment. */
        if ( cipher_index >= 0 && cipher_index <= 4 )
            msg = discordCrypt.blowfish512_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index, mode, pad ),
                secondary_key,
                mode,
                pad,
                true,
                false
            );
        else if ( cipher_index >= 5 && cipher_index <= 9 )
            msg = discordCrypt.aes256_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 5, mode, pad ),
                secondary_key,
                mode,
                pad,
                true,
                false
            );
        else if ( cipher_index >= 10 && cipher_index <= 14 )
            msg = discordCrypt.camellia256_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 10, mode, pad ),
                secondary_key,
                mode,
                pad,
                true,
                false
            );
        else if ( cipher_index >= 15 && cipher_index <= 19 )
            msg = discordCrypt.idea128_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 15, mode, pad ),
                secondary_key,
                mode,
                pad,
                true,
                false
            );
        else if ( cipher_index >= 20 && cipher_index <= 24 )
            msg = discordCrypt.tripledes192_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 20, mode, pad ),
                secondary_key,
                mode,
                pad,
                true,
                false
            );
        else
            throw `Unknown cipher selected: ${cipher_index}`;

        /* Get MAC tag as a hex string. */
        let tag = kmac256(
            new Uint8Array( Buffer.concat( [ primary_key, secondary_key ] ) ),
            new Uint8Array( Buffer.from( msg, 'hex' ) ),
            256,
            customizationParameter
        );

        /* Prepend the authentication tag hex string & convert it to Base64. */
        msg = Buffer.from( tag + msg, 'hex' );

        /* Return the message. */
        return discordCrypt.substituteMessage( msg, true );
    }

    /**
     * @public
     * @desc Dual-decrypts a message using symmetric keys and returns the substituted encoded equivalent.
     * @param {string|Buffer|Array} message The substituted and encoded input message to decrypt.
     * @param {Buffer} primary_key The primary key used for the **second** level of decryption.
     * @param {Buffer} secondary_key The secondary key used for the **first** level of decryption.
     * @param {int} cipher_index The cipher index containing the primary and secondary ciphers used for decryption.
     * @param {string} block_mode The block operation mode of the ciphers.
     *      These can be: [ 'CBC', 'CFB', 'OFB' ].
     * @param {string} padding_mode The padding scheme used to unpad the message to the block length of the cipher.
     *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
     *      If this is enabled and authentication fails, null is returned.
     *      This prepends a 64 bit seed used to derive encryption keys from the initial key.
     * @returns {string|null} Returns the encrypted and substituted ciphertext of the message or null on failure.
     * @throws An exception indicating the error that occurred.
     */
    static symmetricDecrypt( message, primary_key, secondary_key, cipher_index, block_mode, padding_mode ) {
        const customizationParameter = new Uint8Array( Buffer.from( 'DiscordCrypt MAC' ) );
        const crypto = require( 'crypto' );

        /* Performs one of the 5 standard decryption algorithms on the plain text. */
        function handleDecodeSegment(
            message,
            key,
            cipher,
            mode,
            pad,
            output_format = 'utf8',
            is_message_hex = undefined
        ) {
            switch ( cipher ) {
            case 0:
                return discordCrypt.blowfish512_decrypt( message, key, mode, pad, output_format, is_message_hex );
            case 1:
                return discordCrypt.aes256_decrypt( message, key, mode, pad, output_format, is_message_hex );
            case 2:
                return discordCrypt.camellia256_decrypt( message, key, mode, pad, output_format, is_message_hex );
            case 3:
                return discordCrypt.idea128_decrypt( message, key, mode, pad, output_format, is_message_hex );
            case 4:
                return discordCrypt.tripledes192_decrypt( message, key, mode, pad, output_format, is_message_hex );
            default:
                return null;
            }
        }

        let mode, pad;

        /* Convert the block mode. */
        if ( typeof block_mode !== 'string' ) {
            if ( block_mode === 0 )
                mode = 'cbc';
            else if ( block_mode === 1 )
                mode = 'cfb';
            else if ( block_mode === 2 )
                mode = 'ofb';
            else return '';
        }

        /* Convert the padding. */
        if ( typeof padding_mode !== 'string' ) {
            if ( padding_mode === 0 )
                pad = 'pkc7';
            else if ( padding_mode === 1 )
                pad = 'ans2';
            else if ( padding_mode === 2 )
                pad = 'iso1';
            else if ( padding_mode === 3 )
                pad = 'iso9';
            else return '';
        }

        try {
            /* Decode level-1 message to a buffer. */
            message = Buffer.from( discordCrypt.substituteMessage( message ), 'hex' );

            /* Pull off the first 32 bytes as a buffer. */
            let tag = Buffer.from( message.subarray( 0, 32 ) );

            /* Strip off the authentication tag. */
            message = Buffer.from( message.subarray( 32 ) );

            /* Compute the HMAC-SHA3-256 of the cipher text as hex. */
            let computed_tag = Buffer.from(
                kmac256(
                    new Uint8Array( Buffer.concat( [ primary_key, secondary_key ] ) ),
                    new Uint8Array( message ),
                    256,
                    customizationParameter
                ),
                'hex'
            );

            /* Compare the tag for validity. */
            if ( !crypto.timingSafeEqual( computed_tag, tag ) )
                return 1;

            /* Dual decrypt the segment. */
            if ( cipher_index >= 0 && cipher_index <= 4 )
                return handleDecodeSegment(
                    discordCrypt.blowfish512_decrypt( message, secondary_key, mode, pad, 'base64' ),
                    primary_key,
                    cipher_index,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 5 && cipher_index <= 9 )
                return handleDecodeSegment(
                    discordCrypt.aes256_decrypt( message, secondary_key, mode, pad, 'base64' ),
                    primary_key,
                    cipher_index - 5,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 10 && cipher_index <= 14 )
                return handleDecodeSegment(
                    discordCrypt.camellia256_decrypt( message, secondary_key, mode, pad, 'base64' ),
                    primary_key,
                    cipher_index - 10,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 15 && cipher_index <= 19 )
                return handleDecodeSegment(
                    discordCrypt.idea128_decrypt( message, secondary_key, mode, pad, 'base64' ),
                    primary_key,
                    cipher_index - 15,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 20 && cipher_index <= 24 )
                return handleDecodeSegment(
                    discordCrypt.tripledes192_decrypt( message, secondary_key, mode, pad, 'base64' ),
                    primary_key,
                    cipher_index - 20,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            return -3;
        }
        catch ( e ) {
            return 2;
        }
    }

    /* ========================================================= */

}

/* Required for code coverage reports. */
module.exports = { discordCrypt };
