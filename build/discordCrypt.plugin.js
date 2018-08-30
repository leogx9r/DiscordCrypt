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
 * @typedef {Object} WebpackFinder
 * @property {Object} module The module object.
 */

/**
 * @typedef {Object} WebpackPrototypeFinder
 * @property {string[]} prototypes All prototypes to search for.
 */

/**
 * @typedef {Object} WebpackPropertyFinder
 * @property {string[]} properties All properties to search for.
 */

/**
 * @typedef {Object} WebpackDisplayNameFinder
 * @property {string} displayName The display name to search for.
 */

/**
 * @typedef {Object} WebpackModuleIdFinder
 * @property {int} id The ID to locate.
 */

/**
 * @typedef {Object} WebpackDispatchFinder
 * @property {string[]} dispatchNames All dispatch names to search for.
 */

/**
 * @typedef {Object} WebpackModuleSearcher
 * @desc Returns various functions that can scan for webpack modules.
 * @property {WebpackFinder} find Recursively iterates all webpack modules to
 *      the callback function.
 * @property {WebpackPrototypeFinder} findByUniquePrototypes Iterates all modules looking for the
 *      defined prototypes.
 * @property {WebpackPropertyFinder} findByUniqueProperties Iterates all modules look for the
 *      defined properties.
 * @property {WebpackDisplayNameFinder} findByDisplayName Iterates all modules looking for the specified
 *      display name.
 * @property {WebpackModuleIdFinder} findByDispatchToken Iterates all modules looking for the specified dispatch
 *      token by its ID.
 * @property {WebpackDispatchFinder} findByDispatchNames Iterates all modules looking for the specified
 *      dispatch names.
 */

/**
 * @typedef {Object} CachedModules
 * @desc Cached Webpack modules for internal access.
 * @property {Object} NonceGenerator Internal nonce generator used for generating unique IDs from the current time.
 * @property {Object} ChannelStore Internal channel resolver for retrieving a list of all channels available.
 * @property {Object} EmojiStore Internal emoji parser that's used to translate emojis sent in messages.
 * @property {Object} GlobalTypes Internal message action types and constants for events.
 * @property {Object} GuildStore Internal Guild resolver for retrieving a list of all guilds currently in.
 * @property {Object} HighlightJS Internal code based library responsible for highlighting code blocks.
 * @property {Object} MessageCreator Internal message parser that's used to translate tags to Discord symbols.
 * @property {Object} MessageController Internal message controller used to receive, send and delete messages.
 * @property {Object} MessageDispatcher Internal message dispatcher for pending queued messages.
 * @property {Object} MessageQueue Internal message Queue store for pending parsing.
 * @property {Object} UserStore Internal user resolver for retrieving all users known.
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
 * @typedef {Object} UpdateInfo
 * @desc Contains information regarding a blacklisted update.
 * @property {string} version Reported version of the blacklisted update.
 * @property {string} payload The raw update payload.
 * @property {boolean} valid The signature was marked as valid.
 * @property {string} hash Checksum of the update data.
 * @property {string} signature The signed PGP signature for the update payload.
 * @property {string} changelog Reported changes that occurred during this update.
 */

/**
 * @typedef {Object} LocalChannelState
 * @desc Contains per-channel specific information.
 * @property {boolean} autoEncrypt Whether automatic encryption is enabled for this channel.
 */

/**
 * @typedef {Object} Config
 * @desc Contains the configuration data used for the plugin.
 * @property {string} version The version of the configuration.
 * @property {boolean} useEmbeds Whether to use embeds for dispatching encrypted messages.
 * @property {Array<{channelId: string, LocalChannelState}>} channelSettings Settings local to a channel.
 * @property {string} defaultPassword The default key to encrypt or decrypt message with,
 *      if not specifically defined.
 * @property {string} decryptedPrefix This denotes the string that should be prepended to messages
 *      that have been successfully decrypted.
 * @property {string} decryptedColor This denotes the color of a decrypted message's text.
 *      This only applies to messages that have been successfully decrypted.
 * @property {string} encodeMessageTrigger The suffix trigger which, once appended to the message,
 *      forces encryption even if a key is not specifically defined for this channel.
 * @property {number} encryptScanDelay If using timed scanning events in case hooked events fail,
 *      this denotes how often, in milliseconds, to scan the window for new messages and decrypt them.
 * @property {number} encryptMode The index of the ciphers to use for message encryption.
 * @property {string} encryptBlockMode The block operation mode of the ciphers used to encrypt message.
 * @property {boolean} encodeAll If enabled, automatically forces all messages sent to be encrypted if a
 *      ChannelPassword object is defined for the current channel..
 * @property {boolean} localStates Localizes settings to the local channel.
 * @property {string} paddingMode The short-hand padding scheme to used to align all messages to the cipher's
 *      block length.
 * @property {{channelId: string, password: ChannelPassword}} passList Storage containing all channels with
 *      passwords defined for encryption of new messages and decryption of currently encrypted messages.
 * @property {string} up1Host The full URI host of the Up1 service to use for encrypted file uploads.
 * @property {string} up1ApiKey If specified, contains the API key used for authentication with the up1Host.
 * @property {Array<TimedMessage>} timedMessages Contains all logged timed messages pending deletion.
 * @property {number} timedMessageExpires How long after a message is sent should it be deleted in seconds.
 * @property {boolean} automaticUpdates Whether to automatically check for updates.
 * @property {Array<UpdateInfo>} blacklistedUpdates Updates to ignore due to being blacklisted.
 */

/**
 * @typedef {Object} UpdateCallback
 * @desc The function to execute after an update has been retrieved or if an error occurs.
 * @property {UpdateInfo} [info] The update's information if valid.
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
 * @return {boolean} Returns true if the data was parsed successfully.
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
 * @typedef {Object} EmojiDescriptor
 * @desc Indicates an emoji's name and snowflake ID.
 * @property {boolean} animated Whether this emoji is animated.
 * @property {string} formatted The full formatted string for the emoji. ( <:# NAME #:# SNOWFLAKE #> )
 * @property {string} name The actual name of the emoji. Example: "thonk"
 * @property {string} snowflake The integer snowflake ID for this emoji.
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
 * @property {boolean} emoji Whether the message has any parsed emojis within it.
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
 * @typedef {Object} EmojiInfo
 * @desc Contains information of a message containing emojis.
 * @property {boolean} emoji Whether the input message contained any parsed emojis.
 * @property {string} html The raw formatted HTML containing any parsed emoji images.
 */

/**
 * @typedef {Object} LibraryInfo
 * @desc Contains the library and necessary information.
 * @property {boolean} requiresNode Whether this library relies on NodeJS internal support.
 * @property {boolean} requiresBrowser Whether this library is meant to be run in a browser.
 * @property {string} code The raw code for execution defined in the library.
 */

/**
 * @typedef {Object} LibraryDefinition
 * @desc Contains a definition of a raw library executed upon plugin startup.
 * @property {string} name The name of the library file.
 * @property {LibraryInfo} info The library info.
 */

/**
 * @interface
 * @name PatchData
 * @desc Contains local patch data and state of the function.
 * @property {object} thisObject Original `this` value in current call of patched method.
 * @property {Arguments} methodArguments Original `arguments` object in current call of patched
 *      method.
 *      Please, never change function signatures, as it may cause a lot of problems in future.
 * @property {cancelPatch} cancelPatch Function with no arguments and no return value that may be
 *      called to reverse patching of current method. Calling this function prevents running of this
 *      callback on further original method calls.
 * @property {function} originalMethod Reference to the original method that is patched. You can use
 *      it if you need some special usage. You should explicitly provide a value for `this` and any
 *      method arguments when you call this function.
 * @property {function} callOriginalMethod This is a shortcut for calling original method using
 *      `this` and `arguments` from original call.
 * @property {*} returnValue This is a value returned from original function call. This property is
 *      available only in `after` callback or in `instead` callback after calling
 *      `callOriginalMethod` function.
 */

/**
 * @callback PatchCallback
 * @desc A callback that modifies method logic. This callback is called on each call of the original method and is
 *      provided all data about original call. Any of the data can be modified if necessary, but do so wisely.
 * @param {PatchData} data Data object with information about current call and original method that you may need in
 *      your patching callback.
 * @return {*} Makes sense only when used as `instead` parameter in _monkeyPatch. If something other than
 *      `undefined` is returned, the returned value replaces the value of `data.returnValue`.
 *      If used as `before` or `after` parameters, return value is ignored.
 */

/**
 * @module discordCrypt
 * @desc Use a scoped variable to protect the internal state of the plugin.
 * @type {_discordCrypt}
 */
const discordCrypt = ( () => {

    /**
     * @private
     * @desc Master database password. This is a Buffer() containing a 256-bit key.
     * @type {Buffer|null}
     */
    let _masterPassword = null;

    /**
     * @private
     * @desc Message scanning interval handler's index. Used to stop any running handler.
     *      Defined only if hooking of modules failed.
     * @type {int}
     */
    let _scanInterval;

    /**
     * @private
     * @desc The index of the handler used to reload the toolbar.
     *      Defined only if hooking of modules failed.
     * @type {int}
     */
    let _toolbarReloadInterval;

    /**
     * @private
     * @desc The index of the handler used for automatic update checking.
     * @type {int}
     */
    let _updateHandlerInterval;

    /**
     * @private
     * @desc The index of the handler used for timed message deletion.
     * @type {int}
     */
    let _timedMessageInterval;

    /**
     * @private
     * @desc The configuration file currently in use. Only valid after decryption of the configuration database.
     * @type {Config|null}
     */
    let _configFile = null;

    /**
     * @private
     * @desc Used to cache webpack modules.
     * @type {CachedModules}
     */
    let _cachedModules = {};

    /**
     * @private
     * @desc Stores the private key object used in key exchanges.
     * @type {Object}
     */
    let _privateExchangeKey;

    /**
     * @private
     * @desc Stores the compressed PGP public key used for update verification.
     * @type {string}
     */
    let _signingKey = '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';

    /**
     * @private
     * @desc Stores the update data for applying later on.
     * @type {UpdateInfo}
     */
    let _updateData = {};

    /**
     * @private
     * @desc Oddly enough, you're allowed to perform a prototype attack to override the freeze() function.
     *      So just backup the function code here in case it gets attacked in the future.
     * @type {function}
     */
    let _freeze = Object.freeze;

    /**
     * @private
     * @desc Array containing function callbacks to execute when stopping the plugin.
     * @type {Array<function>}
     */
    let _stopCallbacks = [];

    /**
     * @protected
     * @class
     * @desc Main plugin prototype.
     */
    class _discordCrypt
    {

        /* ========================================================= */

        /**
         * @public
         * @desc Initializes an instance of _discordCrypt.
         * @example
         * let instance = new _discordCrypt();
         */
        constructor() {

            /* ============================================ */

            /**
             * Discord class names that changes ever so often because they're douches.
             * These will usually be the culprit if the plugin breaks.
             */

            /**
             * @desc Used to scan each message for an encrypted message.
             * @type {string}
             */
            this._messageMarkupClass = '.markup-2BOw-j .inline';

            /**
             * @desc Used to scan each message for an embedded encrypted message.
             * @type {string}
             */
            this._embedDescriptionClass = '.embedDescription-1Cuq9a';

            /**
             * @desc Used to find the search toolbar to inject all option buttons.
             * @type {string}
             */
            this._searchUiClass = '.search .search-bar';
            /**
             * @desc Used to hook messages being sent.
             * @type {string}
             */
            this._channelTextAreaClass = '.content-yTz4x3 textarea';

            /**
             * @desc Used to assign the correct image class to parsed emojis.
             * @type {string}
             */
            this._emojisClass = 'emoji jumboable da-emoji da-jumboable';

            /**
             * @desc Used to detect if the autocomplete dialog is opened.
             * @type {string}
             */
            this._autoCompleteClass = '.autocomplete-1vrmpx';

            /* ============================================ */

            /**
             * @desc Defines what an encrypted message starts with. Must be 4x UTF-16 bytes.
             * @type {string}
             */
            this._encodedMessageHeader = "⢷⢸⢹⢺";

            /**
             * @desc Defines what a public key message starts with. Must be 4x UTF-16 bytes.
             * @type {string}
             */
            this._encodedKeyHeader = "⢻⢼⢽⢾";

            /**
             * @desc Defines what the header of an encrypted message says.
             * @type {string}
             */
            this._messageHeader = '-----ENCRYPTED MESSAGE-----';

            /**
             * @desc Indexes of each dual-symmetric encryption mode.
             * @type {int[]}
             */
            this._encryptModes = [
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
            this._encryptBlockModes = [
                'CBC', /* Cipher Block-Chaining */
                'CFB', /* Cipher Feedback Mode */
                'OFB', /* Output Feedback Mode */
            ];

            /**
             * @desc Shorthand padding modes for block ciphers referred to in the code.
             * @type {string[]}
             */
            this._paddingModes = [
                'PKC7', /* PKCS #7 */
                'ANS2', /* ANSI X.923 */
                'ISO1', /* ISO-10126 */
                'ISO9', /* ISO-97972 */
            ];

            /**
             * @desc Defines the CSS for the application overlays.
             * @type {string}
             */
            this._appCss =
                `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`;

            /**
             * @desc Contains the raw HTML used to inject into the search descriptor providing menu icons.
             * @type {string}
             */
            this._toolbarHtml =
                `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`;

            /**
             * @desc Contains the raw HTML injected into the overlay to prompt for the master password for database
             *      unlocking.
             * @type {string}
             */
            this._masterPasswordHtml =
                `eNqtUs1uwyAMfhWLqUeUrLt1aS7bA+wVHKANGgUETqu+/SAJSVpNO42DY9n+fjBppL6ClkcmBb9gJBW4u6pg8M5AGIxx7JRSC81mfq5yoWzCnbQy8hfQYzvS3agjI+cP8FbvEiM0/b6UhTMuHF5Opzqdd1aEeoUyGZv9XeKZtU3V7zO2C1U7hpRHj7ZAfHAXT0+QPLBMa+sHArr7pOuT55sLD/ZLjc/OZ2LZ8XWaNGXbn0jYYVTwVTpV8QbTxmbaSEiQA+8w5LsvpuEImyfII0NkW1hG8ICk7XnZ4k1L6g+QNjUKVUnpSTBRhsEkRjT6bCfFbiBydjMxFZ5YX+t6t77AYI0T31zOF+Ud2f/QhCXj2qbfJSoG+fzhRKAVyowG2o8xb6qJYrUzfab4AyMh9Dk=`;

            /**
             * @desc Defines the raw HTML used describing each option menu.
             * @type {string}
             */
            this._settingsMenuHtml =
                `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`;

            /**
             * @desc The Base64 encoded SVG containing the unlocked status icon.
             * @type {string}
             */
            this._unlockIcon = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwI" +
                "DI0IDI0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMTdjMS4xI" +
                "DAgMi0uOSAyLTJzLS45LTItMi0yLTIgLjktMiAyIC45IDIgMiAyem02LTloLTFWNmMwLTIuNzYtMi4yNC01LTUtNVM3IDMuMjQgN" +
                "yA2aDEuOWMwLTEuNzEgMS4zOS0zLjEgMy4xLTMuMSAxLjcxIDAgMy4xIDEuMzkgMy4xIDMuMXYySDZjLTEuMSAwLTIgLjktMiAyd" +
                "jEwYzAgMS4xLjkgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6bTAgMTJINlYxMGgxMnYxMHoiPjwvc" +
                "GF0aD48L3N2Zz4=";

            /**
             * @desc The Base64 encoded SVG containing the locked status icon.
             * @type {string}
             */
            this._lockIcon = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwIDI" +
                "0IDI0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZGVmcz48cGF0aCBkPSJNMCAwaDI" +
                "0djI0SDBWMHoiIGlkPSJhIi8+PC9kZWZzPjxjbGlwUGF0aCBpZD0iYiI+PHVzZSBvdmVyZmxvdz0idmlzaWJsZSIgeGxpbms6aHJ" +
                "lZj0iI2EiLz48L2NsaXBQYXRoPjxwYXRoIGNsaXAtcGF0aD0idXJsKCNiKSIgZD0iTTEyIDE3YzEuMSAwIDItLjkgMi0ycy0uOS0" +
                "yLTItMi0yIC45LTIgMiAuOSAyIDIgMnptNi05aC0xVjZjMC0yLjc2LTIuMjQtNS01LTVTNyAzLjI0IDcgNnYySDZjLTEuMSAwLTI" +
                "gLjktMiAydjEwYzAgMS4xLjkgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6TTguOSA2YzAtMS43MSA" +
                "xLjM5LTMuMSAzLjEtMy4xczMuMSAxLjM5IDMuMSAzLjF2Mkg4LjlWNnpNMTggMjBINlYxMGgxMnYxMHoiLz48L3N2Zz4=";

            /**
             * @desc These contain all _libraries that will be loaded dynamically in the current JS VM.
             * @type {LibraryDefinition}
             */
            this._libraries = {
                'currify.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"eNqdVFFv2yAQ/iuONaWgEit5jUujae2etvZlfbKs1rWhYaLgYWgWOfz3gcFOKuWh3Ys5HXcfd9995xk1otZMCiBgzyhI5fNvUusUY71viaQJ+dtKpbv5PDWiIZQJ0qSz8fJVNoYTGI4shmIBYE54RxKPN+IfEQPKfB7OrHptYDBBUSIRUntOdKJyoPC5Z3dMNHK3Ccf6XMQLl88V34TjbERHON34z1pvWQez2ijF6N4Xby2YWIH9W6USgRQiuSLaKJGMd4kAzos07CePBBSZgccZKWgZLDVYHqbGZ+hQ5I9hyvERjdznmPm8hvG92oHOltD72ehj0edRORZkl9wqJRV4+lYJIXXimm3idJKLLz21F08w11sldwnPatkQnP68v3n4cft4d//r8fv9w91Nirj1cC32peM+TnPdW5v7FoplmdUV56AdB41OteNTCR4CV2UhypEtCcjhIKBFLTomDnw65mwM8i+Ol0MR7ENMUdexF4rAy1xc6YwT8aK3ubi8hBJoVwScqrCgjxNeF8eyfRmwT43TaqcVc7ofGNX4dMawDyDFabsRV2VV2/I9eJOsSZaoUi/mlQjduX5PXiGfjfei+mwGkv+Tg9gHskqbn0g8/iim+UwrJWBQWJBiSkXSbaXhTfJMpqWZpW7o05/iPc1+nEFG09txpIjhr0pVe0CuVxuyWK2XEFG8yumVE4GbNivoYlUe05yc/LpIh4pYxLjGKlrwfMMsrJM5VkXARI54H1sotwxS1JUGDA2lZa2SWnomso6zmoRdOZIIHfn1VMJirGqxQnwUqQYGFnV5OBhrUe9Ydx9UpFG3aQnBZEML838pAQw+"},
            'curve25519.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'openpgp.js': {"requiresNode":true,"requiresBrowser":true,"minify":false,"code":"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"},
            'sha3.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sjcl.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"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"},
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
            return 'leogx9r';
        }

        /**
         * @public
         * @desc Returns the current version of the plugin.
         * @returns {string}
         */
        getVersion() {
            return '1.5.11';
        }

        /**
         * @public
         * @desc Starts the script execution. This is called by BetterDiscord if the plugin is enabled.
         */
        start() {
            /* Backup class instance. */
            const self = this;

            /* Perform idiot-proof check to make sure the user named the plugin `_discordCrypt.plugin.js` */
            if ( !_discordCrypt._validPluginName() ) {
                global.smalltalk.alert(
                    'Hi There! - DiscordCrypt',
                    "Oops!\r\n\r\n" +
                    "It seems you didn't read DiscordCrypt's usage guide. :(\r\n" +
                    "You need to name this plugin exactly as follows to allow it to function correctly.\r\n\r\n" +
                    `\t${_discordCrypt._getPluginName()}\r\n\r\n\r\n` +
                    "You should probably check the usage guide again just in case you missed anything else. :)"
                );
                return;
            }

            /* Perform startup and load the config file if not already loaded. */
            if ( !_configFile ) {
                /* Load the master password. */
                this._loadMasterPassword();

                /* Don't do anything further till we have a configuration file. */
                return;
            }

            /* Don't check for updates if running a debug version. */
            if ( !_discordCrypt._shouldIgnoreUpdates( this.getVersion() ) && _configFile.automaticUpdates ) {
                /* Check for any new updates. */
                this._checkForUpdates();

                /* Add an update handler to check for updates every 60 minutes. */
                _updateHandlerInterval = setInterval( () => {
                    self._checkForUpdates();
                }, 3600000 );
            }

            /* Get module searcher for caching. */
            const searcher = _discordCrypt._getWebpackModuleSearcher();

            /* Resolve and cache all modules needed. */
            _cachedModules = {
                NonceGenerator: searcher
                    .findByUniqueProperties( [ "extractTimestamp", "fromTimestamp" ] ),
                EmojiStore: searcher
                    .findByUniqueProperties( [ 'translateSurrogatesToInlineEmoji', 'getCategories' ] ),
                MessageCreator: searcher
                    .findByUniqueProperties( [ "createMessage", "parse", "unparse" ] ),
                MessageController: searcher
                    .findByUniqueProperties( [ "sendClydeError", "sendBotMessage" ] ),
                MarkdownParser: searcher
                    .findByUniqueProperties( [ "parseInline", "defaultParseBlock" ] ),
                GlobalTypes: searcher
                    .findByUniqueProperties( [ "ActionTypes", "ActivityTypes" ] ),
                MessageDispatcher: searcher
                    .findByUniqueProperties( [ "dispatch", "maybeDispatch", "dirtyDispatch" ] ),
                MessageQueue: searcher
                    .findByUniqueProperties( [ "enqueue", "handleSend", "handleResponse" ] ),
                UserStore: searcher
                    .findByUniqueProperties( [ "getUser", "getUsers", "findByTag" ] ),
                GuildStore: searcher
                    .findByUniqueProperties( [ "getGuild", "getGuilds" ] ),
                ChannelStore: searcher
                    .findByUniqueProperties( [ "getChannel", "getChannels", "getDMFromUserId", 'getDMUserIds' ] ),
                HighlightJS: searcher
                    .findByUniqueProperties( [ "initHighlighting", "highlightBlock", "highlightAuto" ] ),
            };

            /* Throw an error if a cached module can't be found. */
            for ( let prop in _cachedModules ) {
                if ( typeof _cachedModules[ prop ] !== 'object' ) {
                    global.smalltalk.alert( 'Error Loading DiscordCrypt', `Could not find requisite module: ${prop}` );
                    return;
                }
            }

            /* Hook the necessary functions required for functionality. */
            this._hookSetup();

            /* Block tracking and analytics. */
            this._blockTracking();

            /* Process any blocks on an interval since Discord loves to throttle messages. */
            _scanInterval = setInterval( () => {
                self._decodeMessages();
            }, _configFile.encryptScanDelay );

            /* Setup the timed message handler to trigger every 5 seconds. */
            _timedMessageInterval = setInterval( () => {
                /* Get the current time. */
                let n = Date.now();

                /* Loop over each message. */
                _configFile.timedMessages.forEach( ( e, i ) => {
                    /* Skip invalid elements. */
                    if ( !e || !e.expireTime ) {
                        /* Delete the index. */
                        _configFile.timedMessages.splice( i, 1 );

                        /* Update the configuration to the disk. */
                        self._saveConfig();
                    }

                    /* Only continue if the message has been expired. */
                    if ( e.expireTime < n ) {
                        /* Quickly log. */
                        _discordCrypt.log( `Deleting timed message "${_configFile.timedMessages[ i ].messageId}"` );

                        try {
                            /* Delete the message. This will be queued if a rate limit is in effect. */
                            _discordCrypt._deleteMessage( e.channelId, e.messageId, _cachedModules );
                        }
                        catch ( e ) {
                            /* Log the error that occurred. */
                            _discordCrypt.log( `${e.messageId}: ${e.toString()}`, 'error' );
                        }

                        /* Delete the index. */
                        _configFile.timedMessages.splice( i, 1 );

                        /* Update the configuration to the disk. */
                        self._saveConfig();
                    }
                } );

            }, 5000 );

            setImmediate( () => {
                /* Decode all messages immediately. */
                self._decodeMessages();
            } );
        }

        /**
         * @public
         * @desc Stops the script execution.
         *      This is called by BetterDiscord if the plugin is disabled or during shutdown.
         */
        stop() {
            /* Nothing needs to be done since start() wouldn't have triggered. */
            if ( !_discordCrypt._validPluginName() )
                return;

            /* Remove onMessage event handler hook. */
            $( this._channelTextAreaClass ).off( "keydown.dcrypt" );

            /* Unload the decryption interval. */
            clearInterval( _scanInterval );

            /* Unload the timed message handler. */
            clearInterval( _timedMessageInterval );

            /* Unload the update handler. */
            clearInterval( _updateHandlerInterval );

            /* Unload the toolbar reload interval if necessary. */
            if( _toolbarReloadInterval )
                clearInterval( _toolbarReloadInterval );

            /* Unload elements. */
            $( "#dc-overlay" ).remove();
            $( '#dc-file-btn' ).remove();
            $( '#dc-lock-btn' ).remove();
            $( '#dc-passwd-btn' ).remove();
            $( '#dc-exchange-btn' ).remove();
            $( '#dc-settings-btn' ).remove();
            $( '#dc-quick-exchange-btn' ).remove();
            $( '#dc-clipboard-upload-btn' ).remove();

            /* Remove all hooks & clear the storage. */
            for( let i = 0; i < _stopCallbacks.length; i++ )
                _stopCallbacks[ i ]();
            _stopCallbacks = [];

            /* Clear the configuration file. */
            _configFile = null;
        }

        /**
         * @public
         * @desc Triggered when the script has to load resources. This is called once upon Discord startup.
         */
        load() {

            /* Freeze the plugin instance if required. */
            if(
                global.bdplugins &&
                global.bdplugins[ this.getName() ] &&
                global.bdplugins[ this.getName() ].plugin
            ) {
                Object.freeze( bdplugins[ this.getName() ] );
                Object.freeze( bdplugins[ this.getName() ].plugin );
            }

            /* Inject application CSS. */
            _discordCrypt._injectCSS( 'dc-css', _discordCrypt.__zlibDecompress( this._appCss ) );

            /* Reapply the native code for Object.freeze() right before calling these as they freeze themselves. */
            Object.freeze = _freeze;

            /* Load necessary _libraries. */
            _discordCrypt.__loadLibraries( this._libraries );
        }

        /**
         * @public
         * @desc Triggered when the script needs to unload its resources. This is called during Discord shutdown.
         */
        unload() {
            /* Clear the injected CSS. */
            _discordCrypt._clearCSS( 'dc-css' );
        }

        /* ========================================================= */

        /* ================= CONFIGURATION DATA CBS ================ */

        /**
         * @private
         * @desc Returns the default settings for the plugin.
         * @returns {Config}
         */
        _getDefaultConfig() {
            return {
                /* Automatically check for updates. */
                automaticUpdates: true,
                /* Blacklisted updates. */
                blacklistedUpdates: [],
                /* Storage of channel settings */
                channelSettings: {},
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
                /* Default password for servers not set. */
                defaultPassword: "⠓⣭⡫⣮⢹⢮⠖⣦⠬⢬⣸⠳⠜⣍⢫⠳⣂⠙⣵⡘⡕⠐⢫⢗⠙⡱⠁⡷⠺⡗⠟⠡⢴⢖⢃⡙⢺⣄⣑⣗⢬⡱⣴⠮⡃⢏⢚⢣⣾⢎⢩⣙⠁⣶⢁⠷⣎⠇⠦⢃⠦⠇⣩⡅",
                /* Decrypted messages have this string prefixed to it. */
                decryptedPrefix: "🔐 ",
                /* Decrypted messages have this color. */
                decryptedColor: "green",
                /* Use local channel settings */
                localStates: false,
                /* Default padding mode for blocks. */
                paddingMode: 'PKC7',
                /* Password array of objects for users or channels. */
                passList: {},
                /* Internal message list for time expiration. */
                timedMessages: [],
                /* How long after a message is sent to remove it. */
                timedMessageExpires: 0,
                /* Whether to send messages using embedded objects. */
                useEmbeds: false,
                /* Contains the URL of the Up1 client. */
                up1Host: 'https://share.riseup.net',
                /* Contains the API key used for transactions with the Up1 host. */
                up1ApiKey: '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
                /* Current Version. */
                version: this.getVersion(),
            };
        }

        /**
         * @private
         * @desc Checks if the configuration file exists.
         * @returns {boolean} Returns true if the configuration file exists.
         */
        _configExists() {
            /* Attempt to parse the configuration file. */
            let data = bdPluginStorage.get( this.getName(), 'config' );

            /* The returned data must be defined and non-empty. */
            return data && data !== null && data !== '';
        }

        /**
         * @private
         * @desc Loads the configuration file from `DiscordCrypt.config.json` and
         *      adds or removes any properties required.
         * @returns {boolean}
         */
        _loadConfig() {
            _discordCrypt.log( 'Loading configuration file ...' );

            /* Attempt to parse the configuration file. */
            let config = bdPluginStorage.get( this.getName(), 'config' );

            /* Check if the config file exists. */
            if ( !config || config === null || config === '' ) {
                /* File doesn't exist, create a new one. */
                _configFile = this._getDefaultConfig();

                /* Save the config. */
                this._saveConfig();

                /* Nothing further to do. */
                return true;
            }

            try {
                /* Try parsing the decrypted data. */
                _configFile = JSON.parse(
                    _discordCrypt.__zlibDecompress(
                        _discordCrypt.__aes256_decrypt_gcm( config.data, _masterPassword, 'PKC7', 'base64', false ),
                        'base64',
                        'utf8'
                    )
                );
            }
            catch ( err ) {
                _discordCrypt.log( `Decryption of configuration file failed - ${err}`, 'error' );
                return false;
            }

            /* If it fails, return an error. */
            if ( !_configFile || !_configFile.version ) {
                _discordCrypt.log( 'Decryption of configuration file failed.', 'error' );
                return false;
            }

            /* Try checking for each property within the config file and make sure it exists. */
            let defaultConfig = this._getDefaultConfig(), needs_save = false;

            /* Iterate all defined properties in the default configuration file. */
            for ( let prop in defaultConfig ) {
                /* If the defined property doesn't exist in the current configuration file ... */
                if (
                    !_configFile.hasOwnProperty( prop ) ||
                    (
                        typeof _configFile[ prop ] !== typeof defaultConfig[ prop ] &&
                        !Array.isArray( defaultConfig[ prop ] )
                    )
                ) {
                    /* Use the default. */
                    _configFile[ prop ] = defaultConfig[ prop ];

                    /* Show a simple log. */
                    _discordCrypt.log(
                        `Default value added for missing property '${prop}' in the configuration file.`
                    );

                    /* Set the flag for saving. */
                    needs_save = true;
                }
            }

            /* Iterate all defined properties in the current configuration file and remove any undefined ones. */
            for ( let prop in _configFile ) {
                /* If the default configuration doesn't contain this property, delete it as it's unnecessary. */
                if ( !defaultConfig.hasOwnProperty( prop ) ) {
                    /* Delete the property. */
                    delete _configFile[ prop ];

                    /* Show a simple log. */
                    _discordCrypt.log( `Removing unknown property '${prop}' from the configuration file.` );

                    /* Set the flag for saving. */
                    needs_save = true;
                }
            }

            /* Check for version mismatch. */
            if ( _configFile.version !== this.getVersion() ) {
                /* Preserve the old version for logging. */
                let oldVersion = _configFile.version;

                /* Preserve the old password list before updating. */
                let oldCache = _configFile.passList;

                /* Get the most recent default configuration. */
                _configFile = this._getDefaultConfig();

                /* Now restore the password list. */
                _configFile.passList = oldCache;

                /* Set the flag for saving. */
                needs_save = true;

                /* Alert. */
                _discordCrypt.log( `Updated plugin version from v${oldVersion} to v${this.getVersion()}.` );
            }

            /* Save the configuration file if necessary. */
            if ( needs_save )
                this._saveConfig();

            _discordCrypt.log( `Loaded configuration file! - v${_configFile.version}` );

            return true;
        }

        /**
         * @private
         * @desc Saves the configuration file with the current password using AES-256 in GCM mode.
         */
        _saveConfig() {
            /* Encrypt the message using the master password and save the encrypted data. */
            bdPluginStorage.set( this.getName(), 'config', {
                data:
                    _discordCrypt.__aes256_encrypt_gcm(
                        _discordCrypt.__zlibCompress(
                            JSON.stringify( _configFile ),
                            'utf8'
                        ),
                        _masterPassword,
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
        _saveSettings( btn ) {
            /* Save the configuration file. */
            this._saveConfig();

            /* Force decode messages. */
            this._decodeMessages( true );

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
        _resetSettings( btn ) {
            /* Preserve the old password list before resetting. */
            let oldCache = _configFile.passList;

            /* Retrieve the default configuration. */
            _configFile = this._getDefaultConfig();

            /* Restore the old passwords. */
            _configFile.passList = oldCache;

            /* Save the configuration file to update any settings. */
            this._saveConfig();

            /* Force decode messages. */
            this._decodeMessages( true );

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
        _updatePasswords() {
            /* Don't save if the password overlay is not open. */
            if ( $( '#dc-overlay-password' ).css( 'display' ) !== 'block' )
                return;

            let prim = $( "#dc-password-primary" );
            let sec = $( "#dc-password-secondary" );

            /* Check if a primary password has actually been entered. */
            if ( !( prim.val() !== '' && prim.val().length > 1 ) ) {
                delete _configFile.passList[ _discordCrypt._getChannelId() ];

                /* Disable auto-encrypt for that channel */
                this._setAutoEncrypt( false );
            }
            else {
                /* Update the password field for this id. */
                _configFile.passList[ _discordCrypt._getChannelId() ] =
                    _discordCrypt._createPassword( prim.val(), '' );

                /* Only check for a secondary password if the primary password has been entered. */
                if ( sec.val() !== '' && sec.val().length > 1 )
                    _configFile.passList[ _discordCrypt._getChannelId() ].secondary = sec.val();

                /* Update the password toolbar. */
                prim.val( '' );
                sec.val( '' );

                /* Enable auto-encrypt for the channel */
                this._setAutoEncrypt( true );
            }

            /* Save the configuration file and decode any messages. */
            this._saveConfig();

            /* Decode any messages with the new password(s). */
            this._decodeMessages( true );
        }

        /* ========================================================= */

        /* ==================== MAIN CALLBACKS ==================== */

        /**
         * @private
         * @desc Hook Discord's internal event handlers for message decryption.
         * @return {boolean} Returns true if handler events have been hooked.
         */
        _hookMessageCallbacks() {
            /* Find the main switch event dispatcher. */
            let _messageUpdateDispatcher = _discordCrypt._getWebpackModuleSearcher().findByDispatchNames( [
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

            /* Don't proceed if it failed. */
            if ( !_messageUpdateDispatcher ) {
                _discordCrypt.log( `Failed to locate the switch event dispatcher!`, 'error' );
                return false;
            }

            /* Hook the switch event dispatcher. */
            _discordCrypt._hookDispatcher(
                _messageUpdateDispatcher,
                'CHANNEL_SELECT',
                {
                    after: ( e ) => {
                        /* Skip channels not currently selected. */
                        if ( _discordCrypt._getChannelId() !== e.methodArguments[ 0 ].channelId )
                            return;

                        /* Delays are required due to windows being loaded async. */
                        setTimeout(
                            () => {
                                _discordCrypt.log( 'Detected chat switch.', 'debug' );

                                /* Make sure localStates is enabled */
                                if( _configFile.localStates ) {

                                    /* Checks if channel is in channel settings storage and enables it if it isn't. */
                                    if( !_configFile.channelSettings[ _discordCrypt._getChannelId() ] )
                                        _configFile.channelSettings[ _discordCrypt._getChannelId() ] =
                                            { autoEncrypt: true };

                                    /* Update the lock icon since it is local to the channel */
                                    _discordCrypt._updateLockIcon( this );
                                }

                                /* Add the toolbar. */
                                this._loadToolbar();

                                /* Attach the message handler. */
                                this._attachHandler();

                                /* Decrypt any messages. */
                                this._decodeMessages();
                            },
                            1
                        );
                    }
                }
            );

            let messageUpdateEvent = {
                after: ( e ) => {
                    /* Skip channels not currently selected. */
                    if ( _discordCrypt._getChannelId() !== e.methodArguments[ 0 ].channelId )
                        return;

                    /* Delays are required due to windows being loaded async. */
                    setTimeout(
                        () => {
                            /* Decrypt any messages. */
                            this._decodeMessages();
                        },
                        1
                    );
                }
            };

            /* Hook incoming message creation dispatcher. */
            _discordCrypt._hookDispatcher( _messageUpdateDispatcher, 'MESSAGE_CREATE', messageUpdateEvent );
            _discordCrypt._hookDispatcher( _messageUpdateDispatcher, 'MESSAGE_UPDATE', messageUpdateEvent );

            return true;
        }

        /**
         * @private
         * @desc Sets up the hooking methods required for proper plugin functionality.
         */
        _hookSetup() {
            const moduleSearcher = discordCrypt._getWebpackModuleSearcher();

            /* Hook switch events as the main event processor. */
            if ( !this._hookMessageCallbacks() ) {
                /* The toolbar fails to properly load on switches to the friends list. Create an interval to do this. */
                _toolbarReloadInterval = setInterval( () => {
                    self._loadToolbar();
                    self._attachHandler();
                }, 5000 );
            }
            else {
                setImmediate( () => {
                    /* Add the toolbar. */
                    this._loadToolbar();

                    /* Attach the message handler. */
                    this._attachHandler();
                } );
            }

            /* Patch emoji selection to force it to be enabled for full-encryption messages. */
            _discordCrypt._monkeyPatch(
                moduleSearcher.findByUniqueProperties( [ 'isEmojiDisabled' ] ),
                'isEmojiDisabled',
                {
                    instead: ( patchData ) => {
                        if(
                            _discordCrypt._getChannelId() === patchData.methodArguments[ 1 ].id &&
                            this._hasCustomPassword( patchData.methodArguments[ 1 ].id ) &&
                            this._getAutoEncrypt()
                        )
                            return false;

                        return patchData.callOriginalMethod(
                            patchData.methodArguments[ 0 ],
                            patchData.methodArguments[ 1 ]
                        );
                    }
                }
            )
        }

        /**
         * @private
         * @desc Loads the master-password unlocking prompt.
         */
        _loadMasterPassword() {
            const self = this;

            if ( $( '#dc-master-overlay' ).length !== 0 )
                return;

            /* Check if the database exists. */
            const cfg_exists = self._configExists();

            const action_msg = cfg_exists ? 'Unlock Database' : 'Create Database';

            /* Construct the password updating field. */
            $( document.body ).prepend( _discordCrypt.__zlibDecompress( this._masterPasswordHtml ) );

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
                _discordCrypt._onMasterUnlockButtonClicked(
                    self,
                    unlock_btn,
                    cfg_exists,
                    pwd_field,
                    action_msg,
                    master_status
                )
            );

            /* Handle cancel button presses. */
            cancel_btn.click( _discordCrypt._onMasterCancelButtonClicked( self ) );
        }

        /**
         * @private
         * @desc Performs an async update checking and handles actually updating the current version if necessary.
         */
        _checkForUpdates() {
            const self = this;
            const update_check_btn = $( '#dc-update-check-btn' );

            try {

                /* Sanity check in case this isn't defined yet. */
                if( update_check_btn.length ) {
                    /* Update the checking button. */
                    update_check_btn.attr( 'disabled', true );
                    update_check_btn.text( 'Checking For Updates ...' );
                }

                /* Perform the update check. */
                _discordCrypt._checkForUpdate(
                    ( info ) => {

                        /* Sanity check in case this isn't defined yet. */
                        if( update_check_btn.length ) {
                            /* Reset the update check button if necessary. */
                            update_check_btn.attr( 'disabled', false );
                            update_check_btn.text( 'Check For Updates' );
                        }

                        /* Make sure an update was received. */
                        if( !info )
                            return;

                        /* Alert the user of the update and changelog. */
                        $( '#dc-overlay' ).css( 'display', 'block' );
                        $( '#dc-update-overlay' ).css( 'display', 'block' );

                        /* Update the version info. */
                        $( '#dc-new-version' ).text(
                            `New Version: ${info.version === '' ? 'N/A' : info.version} ` +
                            `( #${info.hash.slice( 0, 16 )} - ` +
                            `Update ${info.valid ? 'Verified' : 'Contains Invalid Signature. BE CAREFUL'}! )`
                        );
                        $( '#dc-old-version' ).text( `Current Version: ${self.getVersion()} ` );

                        /* Update the changelog. */
                        let dc_changelog = $( '#dc-changelog' );
                        dc_changelog.val(
                            typeof info.changelog === "string" && info.changelog.length > 0 ?
                                _discordCrypt.__tryParseChangelog( info.changelog, self.getVersion() ) :
                                'N/A'
                        );

                        /* Scroll to the top of the changelog. */
                        dc_changelog.scrollTop( 0 );

                        /* Store the update information in the upper scope. */
                        _updateData = info;
                    },
                    _configFile.blacklistedUpdates
                );
            }
            catch ( ex ) {
                _discordCrypt.log( ex, 'warn' );
            }
        }

        /**
         * @private
         * @desc Updates the auto-encrypt toggle
         * @param {boolean} enable
         */
        _setAutoEncrypt( enable ) {
            if( _configFile.localStates )
                _configFile.channelSettings[ _discordCrypt._getChannelId() ].autoEncrypt = enable;
            else
                _configFile.encodeAll = enable;
        }

        /**
         * @private
         * @desc Returns whether or not auto-encrypt is enabled
         * @returns {boolean}
         */
        _getAutoEncrypt() {
            /* Quick sanity check. */
            if( !_configFile )
                return false;

            /* Fetch the current value depending on if local states are enabled. */
            if( _configFile.localStates )
                return _configFile.channelSettings[ _discordCrypt._getChannelId() ].autoEncrypt;
            else
                return _configFile.encodeAll;
        }

        /**
         * @private
         * @desc Inserts the plugin's option toolbar to the current toolbar and handles all triggers.
         */
        _loadToolbar() {

            /* Skip if the configuration hasn't been loaded. */
            if ( !_configFile )
                return;

            /* Skip if we're not in an active channel. */
            if ( _discordCrypt._getChannelId() === '@me' )
                return;

            /* Add toolbar buttons and their icons if it doesn't exist. */
            if ( $( '#dc-toolbar' ).length !== 0 )
                return;

            /* Inject the toolbar. */
            $( this._searchUiClass )
                .parent()
                .parent()
                .parent()
                .prepend( _discordCrypt.__zlibDecompress( this._toolbarHtml ) );

            /* Cache jQuery results. */
            let dc_passwd_btn = $( '#dc-passwd-btn' ),
                dc_lock_btn = $( '#dc-lock-btn' ),
                dc_svg = $( '.dc-svg' ),
                lock_tooltip = $( '<span>' ).addClass( 'dc-tooltip-text' );

            /* Set the SVG button class. */
            dc_svg.attr( 'class', 'dc-svg' );

            /* Set the initial status icon. */
            if ( dc_lock_btn.length > 0 ) {
                if ( this._getAutoEncrypt() ) {
                    dc_lock_btn.html( Buffer.from( this._lockIcon, 'base64' ).toString( 'utf8' ) );
                    dc_lock_btn.append( lock_tooltip.text( 'Disable Message Encryption' ) );
                }
                else {
                    dc_lock_btn.html( Buffer.from( this._unlockIcon, 'base64' ).toString( 'utf8' ) );
                    dc_lock_btn.append( lock_tooltip.text( 'Enable Message Encryption' ) );
                }

                /* Set the button class. */
                dc_svg.attr( 'class', 'dc-svg' );
            }

            /* Inject the settings. */
            $( document.body ).prepend( _discordCrypt.__zlibDecompress( this._settingsMenuHtml ) );

            /* Also by default, set the about tab to be shown. */
            _discordCrypt._setActiveSettingsTab( 0 );
            _discordCrypt._setActiveExchangeTab( 0 );

            /* Update all settings from the settings panel. */
            $( '#dc-secondary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );
            $( '#dc-primary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
            $( '#dc-settings-cipher-mode' ).val( _configFile.encryptBlockMode.toLowerCase() );
            $( '#dc-settings-padding-mode' ).val( _configFile.paddingMode.toLowerCase() );
            $( '#dc-settings-encrypt-trigger' ).val( _configFile.encodeMessageTrigger );
            $( '#dc-settings-timed-expire' ).val( _configFile.timedMessageExpires );
            $( '#dc-settings-decrypted-prefix' ).val( _configFile.decryptedPrefix );
            $( '#dc-settings-decrypted-color' ).val( _configFile.decryptedColor );
            $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );
            $( '#dc-settings-scan-delay' ).val( _configFile.encryptScanDelay );
            $( '#dc-local-states' ).prop( 'checked', _configFile.localStates );
            $( '#dc-embed-enabled' ).prop( 'checked', _configFile.useEmbeds );

            /* Handle clipboard upload button. */
            $( '#dc-clipboard-upload-btn' ).click( _discordCrypt._onUploadEncryptedClipboardButtonClicked( this ) );

            /* Handle file button clicked. */
            $( '#dc-file-btn' ).click( _discordCrypt._onFileMenuButtonClicked );

            /* Handle alter file path button. */
            $( '#dc-select-file-path-btn' ).click( _discordCrypt._onChangeFileButtonClicked );

            /* Handle file upload button. */
            $( '#dc-file-upload-btn' ).click( _discordCrypt._onUploadFileButtonClicked( this ) );

            /* Handle file button cancelled. */
            $( '#dc-file-cancel-btn' ).click( _discordCrypt._onCloseFileMenuButtonClicked );

            /* Handle Settings tab opening. */
            $( '#dc-settings-btn' ).click( _discordCrypt._onSettingsButtonClicked );

            /* Handle Plugin Settings tab selected. */
            $( '#dc-plugin-settings-btn' ).click( _discordCrypt._onSettingsTabButtonClicked );

            /* Handle Database Settings tab selected. */
            $( '#dc-database-settings-btn' ).click( _discordCrypt._onDatabaseTabButtonClicked( this ) );

            /* Handle Security Settings tab selected. */
            $( '#dc-security-settings-btn' ).click( _discordCrypt._onSecurityTabButtonClicked( this ) );

            /* Handle Automatic Updates button clicked. */
            $( '#dc-automatic-updates-enabled' ).change( _discordCrypt._onAutomaticUpdateCheckboxChanged( this ) );

            /* Handle checking for updates. */
            $( '#dc-update-check-btn' ).click( _discordCrypt._onCheckForUpdatesButtonClicked( this ) );

            /* Handle Database Import button. */
            $( '#dc-import-database-btn' ).click( _discordCrypt._onImportDatabaseButtonClicked( this ) );

            /* Handle Database Export button. */
            $( '#dc-export-database-btn' ).click( _discordCrypt._onExportDatabaseButtonClicked );

            /* Handle Clear Database Entries button. */
            $( '#dc-erase-entries-btn' ).click( _discordCrypt._onClearDatabaseEntriesButtonClicked( this ) );

            /* Handle Settings tab closing. */
            $( '#dc-exit-settings-btn' ).click( _discordCrypt._onSettingsCloseButtonClicked );

            /* Handle Save settings. */
            $( '#dc-settings-save-btn' ).click( _discordCrypt._onSaveSettingsButtonClicked( this ) );

            /* Handle Reset settings. */
            $( '#dc-settings-reset-btn' ).click( _discordCrypt._onResetSettingsButtonClicked( this ) );

            /* Handle Restart-Now button clicking. */
            $( '#dc-restart-now-btn' ).click( _discordCrypt._onUpdateRestartNowButtonClicked );

            /* Handle Restart-Later button clicking. */
            $( '#dc-restart-later-btn' ).click( _discordCrypt._onUpdateRestartLaterButtonClicked );

            /* Handle Ignore-Update button clicking. */
            $( '#dc-ignore-update-btn' ).click( _discordCrypt._onUpdateIgnoreButtonClicked( this ) );

            /* Handle Info tab switch. */
            $( '#dc-tab-info-btn' ).click( _discordCrypt._onExchangeInfoTabButtonClicked );

            /* Handle Keygen tab switch. */
            $( '#dc-tab-keygen-btn' ).click( _discordCrypt._onExchangeKeygenTabButtonClicked );

            /* Handle Handshake tab switch. */
            $( '#dc-tab-handshake-btn' ).click( _discordCrypt._onExchangeHandshakeButtonClicked );

            /* Handle exit tab button. */
            $( '#dc-exit-exchange-btn' ).click( _discordCrypt._onExchangeCloseButtonClicked );

            /* Open exchange menu. */
            $( '#dc-exchange-btn' ).click( _discordCrypt._onOpenExchangeMenuButtonClicked );

            /* Quickly generate and send a public key. */
            $( '#dc-quick-exchange-btn' ).click( _discordCrypt._onQuickHandshakeButtonClicked );

            /* Repopulate the bit length options for the generator when switching handshake algorithms. */
            $( '#dc-keygen-method' ).change( _discordCrypt._onExchangeAlgorithmChanged );

            /* Generate a new key-pair on clicking. */
            $( '#dc-keygen-gen-btn' ).click( _discordCrypt._onExchangeGenerateKeyPairButtonClicked );

            /* Clear the public & private key fields. */
            $( '#dc-keygen-clear-btn' ).click( _discordCrypt._onExchangeClearKeyButtonClicked );

            /* Send the public key to the current channel. */
            $( '#dc-keygen-send-pub-btn' ).click( _discordCrypt._onExchangeSendPublicKeyButtonClicked( this ) );

            /* Paste the data from the clipboard to the public key field. */
            $( '#dc-handshake-paste-btn' ).click( _discordCrypt._onHandshakePastePublicKeyButtonClicked );

            /* Compute the primary and secondary keys. */
            $( '#dc-handshake-compute-btn' ).click( _discordCrypt._onHandshakeComputeButtonClicked( this ) );

            /* Copy the primary and secondary key to the clipboard. */
            $( '#dc-handshake-cpy-keys-btn' ).click( _discordCrypt._onHandshakeCopyKeysButtonClicked );

            /* Apply generated keys to the current channel. */
            $( '#dc-handshake-apply-keys-btn' ).click( _discordCrypt._onHandshakeApplyKeysButtonClicked( this ) );

            /* Show the overlay when clicking the password button. */
            dc_passwd_btn.click( _discordCrypt._onOpenPasswordMenuButtonClicked );

            /* Update the password for the user once clicked. */
            $( '#dc-save-pwd' ).click( _discordCrypt._onSavePasswordsButtonClicked( this ) );

            /* Reset the password for the user to the default. */
            $( '#dc-reset-pwd' ).click( _discordCrypt._onResetPasswordsButtonClicked( this ) );

            /* Hide the overlay when clicking cancel. */
            $( '#dc-cancel-btn' ).click( _discordCrypt._onClosePasswordMenuButtonClicked );

            /* Copy the current passwords to the clipboard. */
            $( '#dc-cpy-pwds-btn' ).click( _discordCrypt._onCopyCurrentPasswordsButtonClicked );

            /* Set whether auto-encryption is enabled or disabled. */
            dc_lock_btn.click( _discordCrypt._onForceEncryptButtonClicked( this ) );
        }

        /**
         * @private
         * @desc Attached a handler to the message area and dispatches encrypted messages if necessary.
         */
        _attachHandler() {
            const self = this;

            /* Get the text area. */
            let textarea = $( this._channelTextAreaClass );

            /* Make sure we got one element. */
            if ( textarea.length !== 1 )
                return;

            /* Replace any old handlers before adding the new one. */
            textarea.off( "keydown.dcrypt" ).on( "keydown.dcrypt", ( function ( e ) {
                let code = e.keyCode || e.which;

                /* Skip if we don't have a valid configuration. */
                if ( !_configFile )
                    return;

                /* Execute on ENTER/RETURN only. */
                if ( code !== 13 )
                    return;

                /* Skip if shift key is down indicating going to a new line. */
                if ( e.shiftKey )
                    return;

                /* Skip if autocomplete dialog is opened. */
                if ( $( self._autoCompleteClass )[ 0 ] )
                    return;

                /* Encrypt the parsed message and send it. */
                if ( !self._sendEncryptedMessage(
                    _cachedModules
                        .MessageCreator
                        .parse( _discordCrypt._getChannelProps(), $( this ).val() ).content
                ) )
                    return;

                /* Clear text field. */
                _discordCrypt._getElementReactOwner( $( 'form' )[ 0 ] ).setState( { textValue: '' } );

                /* Cancel the default sending action. */
                e.preventDefault();
                e.stopPropagation();
            } ) );
        }

        /**
         * @private
         * @desc Determines if a custom password exists for the specified channel.
         * @param {string} channel_id The target channel's ID.
         * @return {boolean} Returns true if a custom password is set.
         */
        _hasCustomPassword( channel_id ) {
            return _configFile.passList[ channel_id ] &&
                _configFile.passList[ channel_id ].primary &&
                _configFile.passList[ channel_id ].secondary;
        }

        /**
         * @private
         * @desc Parses a public key message and adds the exchange button to it if necessary.
         * @param {Object} obj The jQuery object of the current message being examined.
         * @returns {boolean} Returns true.
         */
        _parseKeyMessage( obj ) {
            /* Extract the algorithm info from the message's metadata. */
            let metadata = _discordCrypt.__extractKeyInfo( obj.text().replace( /\r?\n|\r/g, '' ), true );

            /* Sanity check for invalid key messages. */
            if ( metadata === null )
                return true;

            /* Compute the fingerprint of our currently known public key if any to determine if to proceed. */
            let local_fingerprint = _discordCrypt.__sha256( Buffer.from( $( '#dc-pub-key-ta' ).val(), 'hex' ), 'hex' );

            /* Skip if this is our current public key. */
            if ( metadata[ 'fingerprint' ] === local_fingerprint )
                return true;

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
         * @param {string} [prefix] Messages that are successfully decrypted should have this prefix prepended.
         * @param {string} [color] Messages that get successfully decrypted should have this color.
         * @returns {boolean} Returns true if the message has been decrypted.
         */
        _parseSymmetric( obj, primary_key, secondary_key, as_embed, prefix, color ) {
            let message = $( obj );
            let dataMsg;

            /**********************************************************************************************************
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
             *  #1 - Encode( Base64( Encryption Algorithm << 24 | Padding Mode << 16 | Block Mode << 8 | Reserved ) )
             *  #2 - ( 0 - PKCS #7 | 1 = ANSI X9.23 | 2 = ISO 10126 | 3 = ISO97971 )
             *  #3 - Substitute( Base64( ( Key Algorithm Type & 0xff ) + Public Key ) )
             *  #4 - 8 Byte Metadata For Messages Only
             *
             **********************************************************************************************************/

            /* Skip if the message is <= size of the total header. */
            if ( message.text().length <= 12 )
                return false;

            /* Split off the magic. */
            let magic = message.text().slice( 0, 4 );

            /* If this is a public key, just add a button and continue. */
            if ( magic === this._encodedKeyHeader )
                return this._parseKeyMessage( message );

            /* Make sure it has the correct header. */
            if ( magic !== this._encodedMessageHeader )
                return false;

            /* Try to deserialize the metadata. */
            let metadata = _discordCrypt.__metaDataDecode( message.text().slice( 4, 8 ) );

            /* Try looking for an algorithm, mode and padding type. */
            /* Algorithm first. */
            if ( metadata[ 0 ] >= this._encryptModes.length )
                return false;

            /* Cipher mode next. */
            if ( metadata[ 1 ] >= this._encryptBlockModes.length )
                return false;

            /* Padding after. */
            if ( metadata[ 2 ] >= this._paddingModes.length )
                return false;

            /* Decrypt the message. */
            dataMsg = _discordCrypt.__symmetricDecrypt( message.text().replace( /\r?\n|\r/g, '' )
                .substr( 8 ), primary_key, secondary_key, metadata[ 0 ], metadata[ 1 ], metadata[ 2 ], true );

            /* If decryption didn't fail, set the decoded text along with a green foreground. */
            if ( ( typeof dataMsg === 'string' || dataMsg instanceof String ) && dataMsg !== "" ) {
                /* If this is an embed, increase the maximum width of it. */
                if ( as_embed ) {
                    /* Expand the message to the maximum width. */
                    message.parent().parent().parent().parent().css( 'max-width', '100%' );
                }

                /* Process the message and apply all necessary element modifications. */
                dataMsg = this._postProcessMessage( dataMsg, _configFile.up1Host );

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

                /* Decrypted messages get set to the predefined color. */
                if( color && typeof color === 'string' && color.length > 0 )
                    message.css( 'color', color );

                /* If a prefix is being used, add it now. */
                if( prefix && typeof prefix === 'string' && prefix.length > 0 )
                    message.prepend( prefix );
            }
            else {
                /* If it failed, set a red foreground and set a failure message to prevent further retries. */
                if ( dataMsg === 1 )
                    message.text( '🚫 [ ERROR ] AUTHENTICATION OF CIPHER TEXT FAILED !!!' );
                else if ( dataMsg === 2 )
                    message.text( '🚫 [ ERROR ] FAILED TO DECRYPT CIPHER TEXT !!!' );
                else
                    message.text( '🚫 [ ERROR ] DECRYPTION FAILURE. INVALID KEY OR MALFORMED MESSAGE !!!' );
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
        _postProcessMessage( message, embed_link_prefix ) {

            /* Quick jQuery trick to encode special html characters to prevent XSS */
            message = $( '<div/>' ).text( message ).html();

            /* Extract any code blocks from the message. */
            let processed = _discordCrypt.__buildCodeBlockMessage( message );
            let hasCode = processed.code;

            /* Extract any URLs. */
            processed = _discordCrypt.__buildUrlMessage( processed.html, embed_link_prefix );
            let hasUrl = processed.url;

            /* Extract any Emojis. */
            processed = _discordCrypt.__buildEmojiMessage(
                processed.html,
                this._emojisClass,
                _cachedModules.EmojiStore
            );
            let hasEmojis = processed.emoji;

            /* Return the raw HTML. */
            return {
                url: hasUrl,
                code: hasCode,
                emoji: hasEmojis,
                html: processed.html,
            };
        }

        /**
         * @private
         * @desc Iterates all messages in the current channel and tries to decrypt each, skipping cached results.
         */
        _decodeMessages() {
            /* Skip if a valid configuration file has not been loaded. */
            if ( !_configFile || !_configFile.version )
                return;

            /* Save self. */
            const self = this;

            /* Get the current channel ID. */
            let id = _discordCrypt._getChannelId();

            /* Use the default password for decryption if one hasn't been defined for this channel. */
            let primary = Buffer.from(
                _configFile.passList[ id ] && _configFile.passList[ id ].primary ?
                    _configFile.passList[ id ].primary :
                    _configFile.defaultPassword
            );
            let secondary = Buffer.from(
                _configFile.passList[ id ] && _configFile.passList[ id ].secondary ?
                    _configFile.passList[ id ].secondary :
                    _configFile.defaultPassword
            );

            /* Look through each markup element to find an embedDescription. */
            $( this._embedDescriptionClass ).each( ( function () {
                /* Skip parsed messages. */
                if ( $( this ).data( 'dc-parsed' ) !== undefined )
                    return;

                /* Try parsing a symmetric message. */
                self._parseSymmetric(
                    this,
                    primary,
                    secondary,
                    true,
                    _configFile.decryptedPrefix,
                    _configFile.decryptedColor
                );

                /* Set the flag. */
                $( this ).data( 'dc-parsed', true );
            } ) );

            /* Look through markup classes for inline code blocks. */
            $( this._messageMarkupClass ).each( ( function () {
                /* Skip parsed messages. */
                if ( $( this ).data( 'dc-parsed' ) !== undefined )
                    return;

                /* Try parsing a symmetric message. */
                self._parseSymmetric(
                    this,
                    primary,
                    secondary,
                    false,
                    _configFile.decryptedPrefix,
                    _configFile.decryptedColor
                );

                /* Set the flag. */
                $( this ).data( 'dc-parsed', true );
            } ) );
        }

        /**
         * @private
         * @desc Sends an encrypted message to the current channel.
         * @param {string} message The unencrypted message to send.
         * @param {boolean} [force_send] Whether to ignore checking for the encryption trigger and
         *      always encrypt and send.
         * @param {int} [channel_id] If specified, sends the embedded message to this channel instead of the current
         *      channel.
         * @returns {boolean} Returns false if the message failed to be parsed correctly and 0 on success.
         */
        _sendEncryptedMessage( message, force_send = false, channel_id = undefined ) {
            /* Let's use a maximum message size of 1820 instead of 2000 to account for encoding, new line feeds & packet
         header. */
            const maximum_encoded_data = 1820;

            /* Add the message signal handler. */
            const escapeCharacters = [ "/" ];
            const crypto = require( 'crypto' );

            let cleaned;

            /* Skip messages starting with pre-defined escape characters. */
            if ( message.substr( 0, 2 ) === "##" || escapeCharacters.indexOf( message[ 0 ] ) !== -1 )
                return false;

            /* If we're not encoding all messages or we don't have a password, strip off the magic string. */
            if ( force_send === false &&
                ( !_configFile.passList[ _discordCrypt._getChannelId() ] ||
                    !_configFile.passList[ _discordCrypt._getChannelId() ].primary ||
                    !this._getAutoEncrypt() )
            ) {
                /* Try splitting via the defined split-arg. */
                message = message.split( '|' );

                /* Check if the message actually has the split arg. */
                if ( message.length <= 0 )
                    return false;

                /* Check if it has the trigger. */
                if ( message[ message.length - 1 ] !== _configFile.encodeMessageTrigger )
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
            let parsed = _discordCrypt.__extractTags( cleaned, _discordCrypt._getChannelProps() );

            /* Sanity check for messages with just spaces or new line feeds in it. */
            if ( parsed[ 0 ].length !== 0 ) {
                /* Extract the message to be encrypted. */
                cleaned = parsed[ 0 ];
            }

            /* Add content tags. */
            let user_tags = parsed[ 1 ].length > 0 ? parsed[ 1 ] : '';

            /* Get the passwords. */
            let primaryPassword = Buffer.from(
                _configFile.passList[ _discordCrypt._getChannelId() ] ?
                    _configFile.passList[ _discordCrypt._getChannelId() ].primary :
                    _configFile.defaultPassword
            );

            let secondaryPassword = Buffer.from(
                _configFile.passList[ _discordCrypt._getChannelId() ] ?
                    _configFile.passList[ _discordCrypt._getChannelId() ].secondary :
                    _configFile.defaultPassword
            );

            /* If the message length is less than the threshold, we can send it without splitting. */
            if ( ( cleaned.length + 16 ) < maximum_encoded_data ) {
                /* Encrypt the message. */
                let msg = _discordCrypt.__symmetricEncrypt(
                    cleaned,
                    primaryPassword,
                    secondaryPassword,
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    true
                );

                /* Append the header to the message normally. */
                msg = this._encodedMessageHeader + _discordCrypt.__metaDataEncode
                (
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    parseInt( crypto.pseudoRandomBytes( 1 )[ 0 ] )
                ) + msg;

                /* Break up the message into lines. */
                msg = msg.replace( /(.{32})/g, ( e ) => {
                    return `${e}\n`
                } );

                /* Send the message. */
                _discordCrypt._dispatchMessage(
                    _configFile.useEmbeds,
                    msg,
                    this._messageHeader,
                    `v${this.getVersion().replace( '-debug', '' )}`,
                    0x551A8B,
                    user_tags,
                    channel_id,
                    _configFile.timedMessages,
                    _configFile.timedMessageExpires
                );
            }
            else {
                /* Determine how many packets we need to split this into. */
                let packets = _discordCrypt.__splitStringChunks( cleaned, maximum_encoded_data );
                for ( let i = 0; i < packets.length; i++ ) {
                    /* Encrypt the message. */
                    let msg = _discordCrypt.__symmetricEncrypt(
                        packets[ i ],
                        primaryPassword,
                        secondaryPassword,
                        _configFile.encryptMode,
                        _configFile.encryptBlockMode,
                        _configFile.paddingMode,
                        true
                    );

                    /* Append the header to the message normally. */
                    msg = this._encodedMessageHeader + _discordCrypt.__metaDataEncode
                    (
                        _configFile.encryptMode,
                        _configFile.encryptBlockMode,
                        _configFile.paddingMode,
                        parseInt( crypto.pseudoRandomBytes( 1 )[ 0 ] )
                    ) + msg;

                    /* Break up the message into lines. */
                    msg = msg.replace( /(.{32})/g, ( e ) => {
                        return `${e}\n`
                    } );

                    /* Send the message. */
                    _discordCrypt._dispatchMessage(
                        _configFile.useEmbeds,
                        msg,
                        this._messageHeader,
                        `v${this.getVersion().replace( '-debug', '' )}`,
                        0x551A8B,
                        i === 0 ? user_tags : '',
                        channel_id,
                        _configFile.timedMessages,
                        _configFile.timedMessageExpires
                    );
                }
            }

            /* Save the configuration file and store the new message(s). */
            this._saveConfig();

            return true;
        }

        /**
         * @private
         * @desc Block all forms of tracking.
         */
        _blockTracking() {
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
                    let obj = scanner( Array.isArray( name ) ? name : [ name ] );

                    if( Array.isArray( name ) )
                        obj.prototype[ name[ 0 ] ] = fn;
                    else
                        obj.prototype[ name ] = fn;

                    _freeze( obj.prototype );
                }
                catch( e ) {
                    _discordCrypt.log(
                        `Failed to patch prototype: ${Array.isArray( name ) ? name[ 0 ] : name}\n${e}`,
                        'error'
                    );
                }
            };
            /**
             * @protected
             * @desc Patches a specific property with the new function.
             * @param {Array<string>|string} name The name or names of properties to search for.
             *      The first name will be patched if this is an array.
             * @param {function} fn The function to override the call with.
             * @param scanner
             */
            const patchProperty = ( name, fn, scanner ) => {
                try {
                    let obj = scanner( Array.isArray( name ) ? name : [ name ] );

                    if( Array.isArray( name ) )
                        obj[ name[ 0 ] ] = fn;
                    else
                        obj[ name ] = fn;

                    _freeze( obj );
                }
                catch( e ) {
                    _discordCrypt.log(
                        `Failed to patch property: ${Array.isArray( name ) ? name[ 0 ] : name}\n${e}`,
                        'error'
                    );
                }
            };

            /* Retrieve the scanner. */
            let searcher = _discordCrypt._getWebpackModuleSearcher();

            /**
             * @desc Patches a prototype to replace it then seals the object.
             * @param {string} name The name of the prototype to patch.
             * @param {string} message The message to log when the patched method is called.
             */
            const blockPrototype = ( name, message ) => {
                /* Remove quality reports. */
                patchPrototype(
                    name,
                    () => _discordCrypt.log( message, 'info' ),
                    searcher.findByUniquePrototypes
                );
            };

            /**
             * @desc Patches a property to replace it then seals the object.
             * @param {string} name The name of the property to patch.
             * @param {string} message The message to log when the patched method is called.
             * @param {function} fn The optional function to replace with.
             */
            const blockProperty = ( name, message, fn ) => {
                /* Remove quality reports. */
                patchProperty(
                    name,
                    fn ? fn : () => _discordCrypt.log( message, 'info' ),
                    searcher.findByUniqueProperties
                );
            };

            /* Remove quality reports. */
            blockPrototype( '_sendQualityReports', 'Blocked a voice quality report.' );

            /* Remove Raven/Sentry tracking. */
            blockPrototype( '_sendProcessedPayload', 'Blocked a Sentry tracking report.' );

            /* Remove various metadata tracking. */
            blockPrototype( 'trackWithMetadata', 'Blocked metadata tracking.' );
            blockPrototype( 'trackWithGroupMetadata', 'Blocked metadata tracking.' );
            blockPrototype( 'trackWithOverlayMetadata', 'Blocked metadata tracking.' );

            /* Block retrieval of analytics token. */
            blockProperty( 'getAnalyticsToken', '', () => {
                _discordCrypt.log( 'Blocked retrieval of analytics token.', 'info' );
                return '';
            } );

            /* Block sending of BrainTree's analytics. */
            blockProperty( 'sendEvent', '', () => {
                _discordCrypt.log( 'Blocked BrainTree from sending analytics.', 'info' );
                return '';
            } );

            /* Block reporting of suspicious code. */
            blockProperty( 'hasSuspiciousCode', 'Disabling suspicious code reporting', () => false );
        }

        /* ========================================================= */

        /* ================== UI HANDLE CALLBACKS ================== */

        /**
         * @private
         * @desc Attempts to unlock the database upon startup.
         * @param {_discordCrypt} self
         * @param {Object} unlock_btn
         * @param {boolean} cfg_exists
         * @param {Object} pwd_field
         * @param {string} action_msg
         * @param {Object} master_status
         * @return {Function}
         */
        static _onMasterUnlockButtonClicked( self, unlock_btn, cfg_exists, pwd_field, action_msg, master_status ) {
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

                /* Validate the field entered contains some value and meets the requirements. */
                if ( password && !_discordCrypt.__validatePasswordRequisites( password ) ) {
                    unlock_btn.text( action_msg );
                    unlock_btn.attr( 'disabled', false );
                    return;
                }

                /* Hash the password. */
                _discordCrypt.__scrypt
                (
                    Buffer.from( password ),
                    Buffer.from( _discordCrypt.__whirlpool( password, true ), 'hex' ),
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

                            _discordCrypt.log( error.toString(), 'error' );
                            return true;
                        }

                        if ( progress )
                            master_status.css( 'width', `${parseInt( progress * 100 )}%` );

                        if ( pwd ) {
                            /* To test whether this is the correct password or not, we have to attempt to use it. */
                            _masterPassword = Buffer.from( pwd, 'hex' );

                            /* Attempt to load the database with this password. */
                            if ( !self._loadConfig() ) {
                                _configFile = null;

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
         * @private
         * @desc Cancels loading the plugin when the unlocking cancel button is pressed.
         * @param {_discordCrypt} self
         * @return {Function}
         */
        static _onMasterCancelButtonClicked( self ) {
            return () => {
                /* Basically we remove the prompt overlay and load the toolbar but set every element to hidden except
                    the button to reopen the menu. */

                /* These are all buttons we'll be targeting for hiding. */
                let target_btns = [
                    '#dc-clipboard-upload-btn',
                    '#dc-file-btn',
                    '#dc-settings-btn',
                    '#dc-lock-btn',
                    '#dc-passwd-btn',
                    '#dc-exchange-btn',
                    '#dc-quick-exchange-btn'
                ];

                /* Handles reloading of the injected toolbar on switching channels. */
                let injectedInterval;

                /* Remove the prompt overlay. */
                $( '#dc-master-overlay' ).remove();

                /* Do some quick cleanup. */
                _masterPassword = null;
                _configFile = null;

                /* Handle this on an interval for switching channels. */
                injectedInterval = setInterval( () => {
                    /* Skip if the toolbar has already been injected. */
                    if( $( '#dc-toolbar' ).length )
                        return;

                    /* Inject the toolbar. */
                    $( self._searchUiClass )
                        .parent()
                        .parent()
                        .parent()
                        .prepend( _discordCrypt.__zlibDecompress( self._toolbarHtml ) );

                    let dc_db_prompt_btn = $( '#dc-db-prompt-btn' );

                    /* Set the Unlock DB Prompt button to visible. */
                    dc_db_prompt_btn.css( 'display', 'inline' );

                    /* Hide every other button. */
                    target_btns.forEach( id => $( id ).css( 'display', 'none' ) );

                    /* Add the button click event to reopen the menu. */
                    dc_db_prompt_btn.click( function() {
                        /* Clear the interval. */
                        clearInterval( injectedInterval );

                        /* Remove the toolbar. */
                        $( '#dc-toolbar' ).remove();

                        /* Reopen the prompt. */
                        self._loadMasterPassword();
                    } );
                }, 1000 );
            };
        }

        /**
         * @private
         * @desc Opens the file uploading menu.
         */
        static _onFileMenuButtonClicked() {
            /* Show main background. */
            $( '#dc-overlay' ).css( 'display', 'block' );

            /* Show the upload overlay. */
            $( '#dc-overlay-upload' ).css( 'display', 'block' );
        }

        /**
         * @private
         * @desc Opens the file menu selection.
         */
        static _onChangeFileButtonClicked() {
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
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onUploadEncryptedClipboardButtonClicked( self ) {
            return () => {
                /* Since this is an async operation, we need to backup the channel ID before doing this. */
                let channel_id = _discordCrypt._getChannelId();

                /* Upload the clipboard. */
                _discordCrypt.__up1UploadClipboard(
                    _configFile.up1Host,
                    _configFile.up1ApiKey,
                    global.sjcl,
                    ( error_string, file_url, deletion_link ) => {
                        /* Do some sanity checking. */
                        if (
                            error_string !== null ||
                            typeof file_url !== 'string' ||
                            typeof deletion_link !== 'string'
                        ) {
                            global.smalltalk.alert( 'Failed to upload the clipboard!', error_string );
                            return;
                        }

                        /* Format and send the message. */
                        self._sendEncryptedMessage( `${file_url}`, true, channel_id );

                        /* Copy the deletion link to the clipboard. */
                        require( 'electron' ).clipboard.writeText( `Delete URL: ${deletion_link}` );
                    }
                );
            };
        }

        /**
         * @private
         * @desc  Uploads the selected file and sends the encrypted link.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onUploadFileButtonClicked( self ) {
            return () => {
                const fs = require( 'original-fs' );

                let file_path_field = $( '#dc-file-path' );
                let file_upload_btn = $( '#dc-file-upload-btn' );
                let message_textarea = $( '#dc-file-message-textarea' );
                let send_deletion_link = $( '#dc-file-deletion-checkbox' ).is( ':checked' );
                let randomize_file_name = $( '#dc-file-name-random-checkbox' ).is( ':checked' );

                /* Send the additional text first if it's valid. */
                if ( message_textarea.val().length > 0 )
                    self._sendEncryptedMessage( message_textarea.val(), true );

                /* Since this is an async operation, we need to backup the channel ID before doing this. */
                let channel_id = _discordCrypt._getChannelId();

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
                _discordCrypt.__up1UploadFile(
                    file_path_field.val(),
                    _configFile.up1Host,
                    _configFile.up1ApiKey,
                    global.sjcl,
                    ( error_string, file_url, deletion_link ) => {
                        /* Do some sanity checking. */
                        if (
                            error_string !== null ||
                            typeof file_url !== 'string' ||
                            typeof deletion_link !== 'string'
                        ) {
                            /* Set the status text. */
                            file_upload_btn.text( 'Failed to upload the file!' );
                            _discordCrypt.log( error_string, 'error' );

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
                        self._sendEncryptedMessage(
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
        static _onCloseFileMenuButtonClicked() {
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
        static _onSettingsButtonClicked() {
            /* Show main background. */
            $( '#dc-overlay' ).css( 'display', 'block' );

            /* Show the main settings menu. */
            $( '#dc-overlay-settings' ).css( 'display', 'block' );
        }

        /**
         * @private
         * @desc Selects the Plugin Settings tab.
         */
        static _onSettingsTabButtonClicked() {
            /* Select the plugin settings. */
            _discordCrypt._setActiveSettingsTab( 0 );
        }

        /**
         * @private
         * @desc Selects the Database Settings tab and loads key info.
         * @param {_discordCrypt} self
         * @return {Function}
         */
        static _onDatabaseTabButtonClicked( self ) {
            return () => {
                let users, guilds, channels, table;

                /* Cache the table. */
                table = $( '#dc-database-entries' );

                /* Clear all entries. */
                table.html( '' );

                /* Resolve all users, guilds and channels the current user is a part of. */
                users = _cachedModules.UserStore.getUsers();
                guilds = _cachedModules.GuildStore.getGuilds();
                channels = _cachedModules.ChannelStore.getChannels();

                /* Iterate over each password in the configuration. */
                for ( let prop in _configFile.passList ) {
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
                            .text( 'Copy' ),
                        show_fingerprint_btn = $( '<button>' )
                            .addClass( 'dc-button dc-button-small dc-button-inverse' )
                            .text( 'Show Fingerprint' );

                    /* Handle deletion clicks. */
                    delete_btn.click( function () {
                        /* Delete the entry. */
                        delete _configFile.passList[ id ];

                        /* Disable auto-encryption for the channel */
                        _configFile.channelSettings[ id ].autoEncrypt = false;

                        /* Save the configuration. */
                        self._saveConfig();

                        /* Remove the entire row. */
                        delete_btn.parent().parent().remove();
                    } );

                    /* Handle copy clicks. */
                    copy_btn.click( function() {
                        /* Resolve the entry. */
                        let current_keys = _configFile.passList[ id ];

                        /* Write to the clipboard. */
                        require( 'electron' ).clipboard.writeText(
                            `Primary Key: ${current_keys.primary}\n\nSecondary Key: ${current_keys.secondary}`
                        );

                        copy_btn.text( 'Copied Keys' );

                        setTimeout( () => {
                            copy_btn.text( 'Copy' );
                        }, 1000 );
                    } );

                    /* Handle fingerprint calculation. */

                    /* Handle copy clicks. */
                    show_fingerprint_btn.click( function() {
                        /* Resolve the entry. */
                        let currentKeys = _configFile.passList[ id ];

                        /* Calculate the fingerprint using either the Guild ID & Channel or Channel & UserID. */
                        let fingerprint = _discordCrypt.__generateFingerprint(
                            id,
                            currentKeys.primary,
                            id,
                            currentKeys.secondary,
                            5000
                        );

                        global.smalltalk.prompt(
                            'Fingerprint',
                            "<b>N.B. VERIFY THESE OVER A NON-TEXT COMMUNICATION METHOD!</b><br/><br/><br/>" +
                            `Your Fingerprint: [ \`${name}\` ]:\n\n`,
                            fingerprint,
                            { button: [ 'OK' ] }
                        );
                    } );

                    /* Append the button to the Options column. */
                    $( $( element.children()[ 2 ] ).children()[ 0 ] ).append( copy_btn );

                    /* Append the button to the Options column. */
                    $( $( element.children()[ 2 ] ).children()[ 0 ] ).append( delete_btn );

                    /* Append the button to the Options column. */
                    $( $( element.children()[ 2 ] ).children()[ 0 ] ).append( show_fingerprint_btn );

                    /* Append the entire entry to the table. */
                    table.append( element );
                }

                /* Select the database settings. */
                _discordCrypt._setActiveSettingsTab( 1 );
            };
        }

        /**
         * @private
         * @desc Selects the Security Settings tab and loads all blacklisted updates.
         * @param {_discordCrypt} self
         * @return {Function}
         */
        static _onSecurityTabButtonClicked( self ) {
            return () => {
                /* Get the table to show blacklisted updates. */
                let table = $( '#dc-update-blacklist-entries' );

                /* Iterate over all entries. */
                for ( let i = 0; i < _configFile.blacklistedUpdates.length; i++ ) {
                    /* Get the update info. */
                    let updateInfo = _configFile.blacklistedUpdates[ i ];

                    /* Skip empty values.*/
                    if( !updateInfo )
                        continue;

                    /* Create the elements needed for building the row. */
                    let element =
                            $( `<tr><td>${updateInfo.version}</td><td><div style="display:flex;"></div></td></tr>` ),
                        remove_btn = $( '<button>' )
                            .addClass( 'dc-button dc-button-small dc-button-inverse' )
                            .text( 'Remove' ),
                        changelog_btn = $( '<button>' )
                            .addClass( 'dc-button dc-button-small dc-button-inverse' )
                            .text( 'View Changelog' ),
                        info_btn = $( '<button>' )
                            .addClass( 'dc-button dc-button-small dc-button-inverse' )
                            .text( 'Info' );

                    /* Handle the remove entry button clicked. */
                    remove_btn.click( function () {
                        /* Delete the entry. */
                        delete _configFile.blacklistedUpdates[ i ];
                        _configFile.blacklistedUpdates = _configFile.blacklistedUpdates.filter( e => e );

                        /* Save the configuration. */
                        self._saveConfig();

                        /* Remove the entire row. */
                        remove_btn.parent().parent().parent().remove();
                    } );

                    /* Handle the changelog button clicked. */
                    changelog_btn.click( function() {
                        global.smalltalk.alert(
                            `Changes`,
                            _discordCrypt.__tryParseChangelog( updateInfo.changelog, self.getVersion() )
                        );
                    } );

                    /* Handle the signatures button clicked. */
                    info_btn.click( function() {
                        let size = parseFloat( updateInfo.payload.length / 1024.0 ).toFixed( 3 );
                        let key_id = Buffer.from(
                            global
                                .openpgp
                                .key
                                .readArmored( _discordCrypt.__zlibDecompress( _signingKey ) )
                                .keys[ 0 ]
                                .primaryKey
                                .fingerprint
                        )
                            .toString( 'hex' )
                            .toUpperCase();

                        global.smalltalk.alert(
                            'Update Info',
                            `<strong>Version</strong>: ${updateInfo.version}\n\n` +
                            `<strong>Verified</strong>: ${updateInfo.valid ? 'Yes' : 'No'}\n\n` +
                            `<strong>Size</strong>: ${size} KB\n\n` +
                            `<strong>Key ID</strong>: ${key_id}\n\n` +
                            `<strong>Hash</strong>: ${updateInfo.hash}\n\n` +
                            '<code class="hljs dc-code-block" style="background: none !important;">' +
                            `${updateInfo.signature}</code>`
                        );
                    } );

                    /* Add all option buttons to the Options column. */
                    $( $( element.children()[ 1 ] ).children()[ 0 ] ).append( changelog_btn );
                    $( $( element.children()[ 1 ] ).children()[ 0 ] ).append( info_btn );
                    $( $( element.children()[ 1 ] ).children()[ 0 ] ).append( remove_btn );

                    /* Add the row to the table. */
                    table.append( element );
                }

                /* Set the current state of automatic updates. */
                $( '#dc-automatic-updates-enabled' ).prop( 'checked', _configFile.automaticUpdates );

                /* Select the security settings. */
                _discordCrypt._setActiveSettingsTab( 2 );
            };
        }

        /**
         * @private
         * @desc Toggles the automatic update checking function.
         * @param self
         * @return {Function}
         */
        static _onAutomaticUpdateCheckboxChanged( self ) {
            return () => {
                /* Set the state. */
                _configFile.automaticUpdates = $( '#dc-automatic-updates-enabled' )
                    .is( ':checked' );

                /* Save the configuration. */
                self._saveConfig();

                /* Log. */
                _discordCrypt.log( `${_configFile.automaticUpdates ? 'En' : 'Dis'}abled automatic updates.`, 'debug' );

                /* Skip if we don't need to update. */
                if( !_discordCrypt._shouldIgnoreUpdates( self.getVersion() ) ) {
                    /* If we're doing automatic updates, make sure an interval is set. */
                    if( _configFile.automaticUpdates ) {
                        /* Only do this if none is defined. */
                        if( !_updateHandlerInterval ) {
                            /* Add an update handler to check for updates every 60 minutes. */
                            _updateHandlerInterval = setInterval( () => {
                                self._checkForUpdates();
                            }, 3600000 );
                        }
                    }
                    /* Make sure no interval is defined. */
                    else if( _updateHandlerInterval ) {
                        /* Make sure to clear all intervals. */
                        clearInterval( _updateHandlerInterval );
                        _updateHandlerInterval = null;
                    }
                }
            }
        }

        /**
         * @private
         * @desc Checks for updates immediately.
         * @param self
         * @return {Function}
         */
        static _onCheckForUpdatesButtonClicked( self ) {
            return () => {
                /* Simply call the wrapper, everything else will be handled by this. */
                self._checkForUpdates();
            }
        }

        /**
         * @private
         * @desc Opens a file dialog to import a JSON encoded entries file.
         * @param self
         * @return {Function}
         */
        static _onImportDatabaseButtonClicked( self ) {
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
                        _discordCrypt.log( `Error reading JSON file '${file} ...`, 'warn' );
                        continue;
                    }

                    /* Make sure the root element of entries exists. */
                    if ( !data._discordCrypt_entries || !data._discordCrypt_entries.length )
                        continue;

                    /* Iterate all entries. */
                    for ( let j = 0; j < data._discordCrypt_entries.length; j++ ) {
                        let e = data._discordCrypt_entries[ j ];

                        /* Skip invalid entries. */
                        if ( !e.id || !e.primary || !e.secondary )
                            continue;

                        /* Determine if to count this as an import or an update which aren't counted. */
                        if ( !_configFile.passList.hasOwnProperty( e.id ) ) {
                            /* Update the number imported. */
                            imported++;
                        }

                        /* Add it to the configuration file. */
                        _configFile.passList[ e.id ] = _discordCrypt._createPassword( e.primary, e.secondary );
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
                    _discordCrypt._onDatabaseTabButtonClicked( self )();

                    /* Save the configuration. */
                    self._saveConfig();
                }
            };
        }

        /**
         * @private
         * @desc Opens a file dialog to import a JSON encoded entries file.
         */
        static _onExportDatabaseButtonClicked() {
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
            let data = { _discordCrypt_entries: [] },
                entries;

            /* Iterate each entry in the configuration file. */
            for ( let prop in _configFile.passList ) {
                let e = _configFile.passList[ prop ];

                /* Insert the entry to the list. */
                data._discordCrypt_entries.push( {
                    id: prop,
                    primary: e.primary,
                    secondary: e.secondary
                } );
            }

            /* Update the entry count. */
            entries = data._discordCrypt_entries.length;

            try {
                /* Try writing the file. */
                fs.writeFileSync( file, JSON.stringify( data, null, '    ' ) );

                /* Update the button's text. */
                export_btn.text( `Exported (${entries}) ${entries === 1 ? 'Entry' : 'Entries'}` );
            }
            catch ( e ) {
                /* Log an error. */
                _discordCrypt.log( `Error exporting entries: ${e.toString()}`, 'error' );

                /* Update the button's text. */
                export_btn.text( 'Error: See Console' );
            }

            /* Reset the button's text. */
            setTimeout( () => {
                export_btn.text( 'Export Database' );
            }, 1000 );
        }

        /**
         * @private
         * @desc Clears all entries in the database.
         * @param self
         * @return {Function}
         */
        static _onClearDatabaseEntriesButtonClicked( self ) {
            return () => {
                /* Cache the button. */
                let erase_entries_btn = $( '#dc-erase-entries-btn' );

                /* Remove all entries. */
                _configFile.passList = {};

                /* Clear the table. */
                $( '#dc-database-entries' ).html( '' );

                /* Save the database. */
                self._saveConfig();

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
        static _onSettingsCloseButtonClicked() {
            /* Select the plugin settings. */
            _discordCrypt._setActiveSettingsTab( 0 );

            /* Hide main background. */
            $( '#dc-overlay' ).css( 'display', 'none' );

            /* Hide the main settings menu. */
            $( '#dc-overlay-settings' ).css( 'display', 'none' );
        }

        /**
         * @private
         * @desc Saves all settings.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onSaveSettingsButtonClicked( self ) {
            return () => {

                /* Cache jQuery results. */
                let dc_primary_cipher = $( '#dc-primary-cipher' ),
                    dc_secondary_cipher = $( '#dc-secondary-cipher' ),
                    dc_master_password = $( '#dc-master-password' ),
                    dc_save_settings_btn = $( '#dc-settings-save-btn' );

                /* Update all settings from the settings panel. */
                _configFile.timedMessageExpires = parseInt( $( '#dc-settings-timed-expire' ).val() );
                _configFile.encryptScanDelay = parseInt( $( '#dc-settings-scan-delay' ).val() );
                _configFile.encodeMessageTrigger = $( '#dc-settings-encrypt-trigger' ).val();
                _configFile.decryptedPrefix = $( '#dc-settings-decrypted-prefix' ).val();
                _configFile.decryptedColor = $( '#dc-settings-decrypted-color' ).val();
                _configFile.encryptBlockMode = $( '#dc-settings-cipher-mode' ).val();
                _configFile.defaultPassword = $( '#dc-settings-default-pwd' ).val();
                _configFile.paddingMode = $( '#dc-settings-padding-mode' ).val();
                _configFile.useEmbeds = $( '#dc-embed-enabled' ).is( ':checked' );
                _configFile.localStates = $( '#dc-local-states' ).is( ':checked' );
                _configFile.encryptMode = _discordCrypt
                    .__cipherStringToIndex( dc_primary_cipher.val(), dc_secondary_cipher.val() );

                dc_primary_cipher.val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
                dc_secondary_cipher.val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );

                /* Remove all channel settings if disabled */
                if( !_configFile.localStates )
                    _configFile.channelSettings = {};

                /* Checks if channel is in channel settings storage and adds it*/
                else if( !_configFile.channelSettings[ _discordCrypt._getChannelId() ] )
                    _configFile.channelSettings[ _discordCrypt._getChannelId() ] =
                        { autoEncrypt: true };

                /* Update icon */
                _discordCrypt._updateLockIcon( self );

                /* Handle master password updates if necessary. */
                if ( dc_master_password.val() !== '' ) {
                    let password = dc_master_password.val();

                    /* Ensure the password meets the requirements. */
                    if( !_discordCrypt.__validatePasswordRequisites( password ) )
                        return;

                    /* Reset the password field. */
                    dc_master_password.val( '' );

                    /* Disable the button since this takes a while. */
                    dc_save_settings_btn.attr( 'disabled', true );

                    /* Hash the password. */
                    _discordCrypt.__scrypt
                    (
                        Buffer.from( password ),
                        Buffer.from( _discordCrypt.__whirlpool( password, true ), 'hex' ),
                        32,
                        4096,
                        8,
                        1,
                        ( error, progress, pwd ) => {
                            /* Enable the button. */
                            dc_save_settings_btn.attr( 'disabled', false );

                            if ( error ) {
                                /* Alert the user. */
                                global.smalltalk.alert(
                                    'DiscordCrypt Error',
                                    'Error setting the new database password. Check the console for more info.'
                                );

                                _discordCrypt.log( error.toString(), 'error' );

                                return true;
                            }

                            if ( pwd ) {
                                /* Now update the password. */
                                _masterPassword = Buffer.from( pwd, 'hex' );

                                /* Save the configuration file and update the button text. */
                                self._saveSettings( dc_save_settings_btn );
                            }

                            return false;
                        }
                    );
                }
                else {
                    /* Save the configuration file and update the button text. */
                    self._saveSettings( dc_save_settings_btn );
                }
            };
        }

        /**
         * @private
         * @desc Resets the user settings to their default values.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onResetSettingsButtonClicked( self ) {
            return () => {
                /* Resets the configuration file and update the button text. */
                self._resetSettings( $( '#dc-settings-reset-btn' ) );

                /* Update all settings from the settings panel. */
                $( '#dc-secondary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );
                $( '#dc-primary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
                $( '#dc-settings-cipher-mode' ).val( _configFile.encryptBlockMode.toLowerCase() );
                $( '#dc-settings-padding-mode' ).val( _configFile.paddingMode.toLowerCase() );
                $( '#dc-settings-encrypt-trigger' ).val( _configFile.encodeMessageTrigger );
                $( '#dc-settings-timed-expire' ).val( _configFile.timedMessageExpires );
                $( '#dc-settings-decrypted-prefix' ).val( _configFile.decryptedPrefix );
                $( '#dc-settings-decrypted-color' ).val( _configFile.decryptedColor );
                $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );
                $( '#dc-settings-scan-delay' ).val( _configFile.encryptScanDelay );
                $( '#dc-embed-enabled' ).prop( 'checked', _configFile.useEmbeds );
                $( '#dc-local-states' ).prop( 'checked', _configFile.localStates );
                $( '#dc-master-password' ).val( '' );
            };
        }

        /**
         * @private
         * @desc Applies the update & restarts the app by performing a window.location.reload()
         */
        static _onUpdateRestartNowButtonClicked() {
            const replacePath = require( 'path' )
                .join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );
            const fs = require( 'fs' );

            /* Replace the file. */
            fs.writeFile( replacePath, _updateData.payload, ( err ) => {
                if ( err ) {
                    _discordCrypt.log(
                        "Unable to replace the target plugin. " +
                        `( ${err} )\nDestination: ${replacePath}`,
                        'error'
                    );
                    global.smalltalk.alert( 'Error During Update', 'Failed to apply the update!' );
                }
            } );

            /* Window reload is simple enough. */
            location.reload();
        }

        /**
         * @private
         * @desc Applies the update & closes the upload available panel.
         */
        static _onUpdateRestartLaterButtonClicked() {
            const replacePath = require( 'path' )
                .join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );
            const fs = require( 'fs' );

            /* Replace the file. */
            fs.writeFile( replacePath, _updateData.payload, ( err ) => {
                if ( err ) {
                    _discordCrypt.log(
                        "Unable to replace the target plugin. " +
                        `( ${err} )\nDestination: ${replacePath}`,
                        'error'
                    );
                    global.smalltalk.alert( 'Error During Update', 'Failed to apply the update!' );
                }
            } );

            /* Also reset any opened tabs. */
            _discordCrypt._setActiveSettingsTab( 0 );
            _discordCrypt._setActiveExchangeTab( 0 );

            /* Hide the update and changelog. */
            $( '#dc-overlay' ).css( 'display', 'none' );
            $( '#dc-update-overlay' ).css( 'display', 'none' );
        }

        /**
         * @private
         * @desc Adds the upper scoped update info to the blacklist, saves the configuration file and
         *      closes the update window.
         * @param self
         * @return {Function}
         */
        static _onUpdateIgnoreButtonClicked( self ) {
            return () => {
                /* Clear out the needless data which isn't actually needed to validate a blacklisted update. */
                _updateData.payload = '';

                /* Add the blacklist to the configuration file. */
                _configFile.blacklistedUpdates.push( _updateData );

                /* Save the configuration. */
                self._saveConfig();

                /* Also reset any opened tabs. */
                _discordCrypt._setActiveSettingsTab( 0 );
                _discordCrypt._setActiveExchangeTab( 0 );

                /* Hide the update and changelog. */
                $( '#dc-overlay' ).css( 'display', 'none' );
                $( '#dc-update-overlay' ).css( 'display', 'none' );
            };
        }

        /**
         * @private
         * @desc Switches assets to the Info tab.
         */
        static _onExchangeInfoTabButtonClicked() {
            /* Switch to tab 0. */
            _discordCrypt._setActiveExchangeTab( 0 );
        }

        /**
         * @private
         * @desc Switches assets to the Key Exchange tab.
         */
        static _onExchangeKeygenTabButtonClicked() {
            /* Switch to tab 1. */
            _discordCrypt._setActiveExchangeTab( 1 );
        }

        /**
         * @private
         * @desc Switches assets to the Handshake tab.
         */
        static _onExchangeHandshakeButtonClicked() {
            /* Switch to tab 2. */
            _discordCrypt._setActiveExchangeTab( 2 );
        }

        /**
         * @private
         * @desc Closes the key exchange menu.
         */
        static _onExchangeCloseButtonClicked() {
            /* Hide main background. */
            $( '#dc-overlay' ).css( 'display', 'none' );

            /* Hide the entire exchange key menu. */
            $( '#dc-overlay-exchange' ).css( 'display', 'none' );
        }

        /**
         * @private
         * @desc Opens the key exchange menu.
         */
        static _onOpenExchangeMenuButtonClicked() {
            /* Show background. */
            $( '#dc-overlay' ).css( 'display', 'block' );

            /* Show main menu. */
            $( '#dc-overlay-exchange' ).css( 'display', 'block' );
        }

        /**
         * @private
         * @desc Generates and sends a new public key.
         */
        static _onQuickHandshakeButtonClicked() {
            /* Don't bother opening a menu. Just generate the key. */
            $( '#dc-keygen-gen-btn' ).click();

            /* Now send it. */
            $( '#dc-keygen-send-pub-btn' ).click();
        }

        /**
         * @private
         * @desc Switches the key lengths to their correct values.
         */
        static _onExchangeAlgorithmChanged() {
            /* Variable bit lengths. */
            let dh_bl = _discordCrypt.__getDHBitSizes(), ecdh_bl = _discordCrypt.__getECDHBitSizes();

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
                    dc_keygen_algorithm.append( new Option( v, v, i === ( ecdh_bl.length - 1 ) ) );
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
        static _onExchangeGenerateKeyPairButtonClicked() {
            let dh_bl = _discordCrypt.__getDHBitSizes(), ecdh_bl = _discordCrypt.__getECDHBitSizes();
            let max_salt_len = 32, min_salt_len = 16, salt_len;
            let index, raw_buffer, pub_buffer;
            let key, crypto = require( 'crypto' );

            let dc_keygen_method = $( '#dc-keygen-method' ),
                dc_keygen_algorithm = $( '#dc-keygen-algorithm' );

            /* Get the current algorithm. */
            switch ( dc_keygen_method.val() ) {
            case 'dh':
                /* Generate a new Diffie-Hellman RSA key from the bit size specified. */
                key = _discordCrypt.__generateDH( parseInt( dc_keygen_algorithm.val() ) );

                /* Calculate the index number starting from 0. */
                index = dh_bl.indexOf( parseInt( dc_keygen_algorithm.val() ) );
                break;
            case 'ecdh':
                /* Generate a new Elliptic-Curve Diffie-Hellman key from the bit size specified. */
                key = _discordCrypt.__generateECDH( parseInt( dc_keygen_algorithm.val() ) );

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
            _privateExchangeKey = key;

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
        static _onExchangeClearKeyButtonClicked() {
            /* Clear the key textareas. */
            $( '#dc-pub-key-ta' ).val( '' );
            $( '#dc-priv-key-ta' ).val( '' );
        }

        /**
         * @private
         * @desc Sends the currently generate public key in the correct format.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onExchangeSendPublicKeyButtonClicked( self ) {
            return () => {

                /* Cache jQuery results. */
                let dc_pub_key_ta = $( '#dc-pub-key-ta' );

                /* Don't bother if it's empty. */
                if ( dc_pub_key_ta.val() === '' )
                    return;

                /* The text area stores a hex encoded binary. Convert it to a buffer prior to encoding. */
                let message = Buffer.from( dc_pub_key_ta.val(), 'hex' );

                /* Add the header to the message and encode it. */
                message = self._encodedKeyHeader + _discordCrypt.__substituteMessage( message, true );

                /* Split the message by adding a new line every 32 characters like a standard PGP message. */
                let formatted_message = message.replace( /(.{32})/g, e => `${e}\n` );

                /* Calculate the algorithm string. */
                let algo_str = `${$( '#dc-keygen-method' ).val() !== 'ecdh' ? 'DH-' : 'ECDH-'}` +
                    `${$( '#dc-keygen-algorithm' ).val()}`;

                /* Construct header & footer elements. */
                let header = `-----BEGIN ${algo_str} PUBLIC KEY-----`,
                    footer = `-----END ${algo_str} PUBLIC KEY----- | v${self.getVersion().replace( '-debug', '' )}`;

                /* Send the message. */
                _discordCrypt._dispatchMessage(
                    _configFile.useEmbeds,
                    formatted_message,
                    header,
                    footer,
                    0x720000,
                    '',
                    undefined,
                    _cachedModules,
                    _configFile.timedMessages,
                    _configFile.timedMessageExpires
                );

                /* Save the configuration file and store the new message. */
                self._saveConfig();

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
        static _onHandshakePastePublicKeyButtonClicked() {
            $( '#dc-handshake-ppk' ).val( require( 'electron' ).clipboard.readText() );
        }

        /**
         * @private
         * @desc Computes a shared secret and generates passwords based on a DH/ECDH key exchange.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onHandshakeComputeButtonClicked( self ) {
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
                    const charset = _discordCrypt.__getBraille().splice( 16, 64 );
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
                        .slice( 0, 4 ) !== self._encodedKeyHeader
                )
                    return;

                /* Snip off the header. */
                let blob = dc_handshake_ppk.val().replace( /\r?\n|\r/g, "" ).slice( 4 );

                /* Skip if invalid braille encoded message. */
                if ( !_discordCrypt.__isValidBraille( blob ) )
                    return;

                try {
                    /* Decode the message. */
                    value = Buffer.from( _discordCrypt.__substituteMessage( blob ), 'hex' );
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
                if ( !_discordCrypt.__isValidExchangeAlgorithm( algorithm ) ) {
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
                    `Exchange Algorithm: ${_discordCrypt.__indexToExchangeAlgorithmString( algorithm )}`
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
                if ( !_privateExchangeKey || _privateExchangeKey === undefined ||
                    typeof _privateExchangeKey.computeSecret === 'undefined' ) {
                    /* Update the text. */
                    dc_handshake_compute_btn.text( 'Failed To Calculate Private Key!' );
                    setTimeout( ( function () {
                        dc_handshake_compute_btn.text( 'Compute Secret Keys' );
                    } ), 1000 );
                    return;
                }

                /* Compute the local secret as a hex string. */
                let derived_secret = _discordCrypt.__computeExchangeSharedSecret(
                    _privateExchangeKey,
                    payload,
                    false,
                    false
                );

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
                    global.sha3.sha3_256( isUserSaltPrimary ? user_salt : salt, true ),
                    'hex'
                );
                let secondary_hash = Buffer.from(
                    global.sha3.sha3_512( isUserSaltPrimary ? salt : user_salt, true ),
                    'hex'
                );

                /* Global progress for async callbacks. */
                let primary_progress = 0, secondary_progress = 0;

                /* Calculate the primary key. */
                _discordCrypt.__scrypt(
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
                                _discordCrypt.__entropicBitLength( key.toString( 'base64' ) )
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
                _discordCrypt.__scrypt(
                    secondary_password,
                    secondary_hash,
                    256,
                    3072,
                    8,
                    1,
                    ( error, progress, key ) => {
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
                            $( '#dc-exchange-status' )
                                .css( 'width', `${parseInt( primary_progress + secondary_progress )}%` );
                        }

                        if ( key ) {
                            /* Generate a quality report and apply the password. */
                            $( '#dc-handshake-sec-lbl' ).text( `Secondary Key: ( Quality - ${
                                _discordCrypt.__entropicBitLength( key.toString( 'base64' ) )
                            } Bits )` );
                            $( '#dc-handshake-secondary-key' ).val( key.toString( 'base64' ) );
                        }

                        return false;
                    }
                );

                /* Update the text. */
                dc_handshake_compute_btn.text( 'Generating Keys ...' );

                /* Finally clear all volatile information. */
                _privateExchangeKey = undefined;
                dc_handshake_ppk.val( '' );
                dc_priv_key_ta.val( '' );
                dc_pub_key_ta.val( '' );
            };
        }

        /**
         * @private
         * @desc Copies the currently generated passwords from a key exchange to the clipboard then erases them.
         */
        static _onHandshakeCopyKeysButtonClicked() {
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
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onHandshakeApplyKeysButtonClicked( self ) {
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
                let pwd = _discordCrypt._createPassword(
                    dc_handshake_primary_key.val(),
                    dc_handshake_secondary_key.val()
                );
                dc_handshake_primary_key.val( '' );
                dc_handshake_secondary_key.val( '' );

                /* Enable auto-encryption on the channel */
                self._setAutoEncrypt( true );

                /* Apply the passwords and save the config. */
                _configFile.passList[ _discordCrypt._getChannelId() ] = pwd;
                self._saveConfig();

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
                    _discordCrypt._setActiveExchangeTab( 0 );
                } ), 1000 );
            }
        }

        /**
         * @private
         * @desc Opens the password editor menu.
         */
        static _onOpenPasswordMenuButtonClicked() {
            $( '#dc-overlay' ).css( 'display', 'block' );
            $( '#dc-overlay-password' ).css( 'display', 'block' );
        }

        /**
         * @private
         * @desc Saves the entered passwords for the current channel or DM.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onSavePasswordsButtonClicked( self ) {
            return () => {
                let btn = $( '#dc-save-pwd' );

                /* Update the password and save it. */
                self._updatePasswords();

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
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onResetPasswordsButtonClicked( self ) {
            return () => {
                let btn = $( '#dc-reset-pwd' );

                /* Disable auto-encrypt for the channel */
                self._setAutoEncrypt( false );

                /* Reset the configuration for this user and save the file. */
                delete _configFile.passList[ _discordCrypt._getChannelId() ];
                self._saveConfig();

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
        static _onClosePasswordMenuButtonClicked() {
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
         * @returns {Function}
         */
        static _onCopyCurrentPasswordsButtonClicked() {
            let currentKeys = _configFile.passList[ _discordCrypt._getChannelId() ];

            /* If no password is currently generated, write the default key. */
            if ( !currentKeys ) {
                require( 'electron' ).clipboard.writeText( `Default Password: ${_configFile.defaultPassword}` );
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
        }

        /**
         * @private
         * @desc Enables or disables automatic message encryption.
         * @param {_discordCrypt} self
         * @returns {Function}
         */
        static _onForceEncryptButtonClicked( self ) {
            return () => {
                /* Cache jQuery results. */
                let dc_lock_btn = $( '#dc-lock-btn' ), new_tooltip = $( '<span>' ).addClass( 'dc-tooltip-text' );

                /* Update the icon and toggle. */
                if ( !self._getAutoEncrypt() ) {
                    dc_lock_btn.html( Buffer.from( self._lockIcon, 'base64' ).toString( 'utf8' ) );
                    dc_lock_btn.append( new_tooltip.text( 'Disable Message Encryption' ) );
                    self._setAutoEncrypt( true );
                }
                else {
                    dc_lock_btn.html( Buffer.from( self._unlockIcon, 'base64' ).toString( 'utf8' ) );
                    dc_lock_btn.append( new_tooltip.text( 'Enable Message Encryption' ) );
                    self._setAutoEncrypt( false );
                }

                /* Save config. */
                self._saveConfig();
            };
        }

        /**
         * @private
         * @desc Updates the lock icon
         */
        static _updateLockIcon( self ) {
            /* Cache jQuery results. */
            let dc_lock_btn = $( '#dc-lock-btn' ), tooltip = $( '<span>' ).addClass( 'dc-tooltip-text' );

            /* Update the icon based on the channel */
            if ( self._getAutoEncrypt() ) {
                dc_lock_btn.html( Buffer.from( self._lockIcon, 'base64' ).toString( 'utf8' ) );
                dc_lock_btn.append( tooltip.text( 'Disable Message Encryption' ) );
            }
            else {
                dc_lock_btn.html( Buffer.from( self._unlockIcon, 'base64' ).toString( 'utf8' ) );
                dc_lock_btn.append( tooltip.text( 'Enable Message Encryption' ) );
            }

            /* Set the button class. */
            $( '.dc-svg' ).attr( 'class', 'dc-svg' );
        }

        /**
         * @private
         * @desc Sets the active tab index in the settings menu.
         * @param {int} index The index ( 0-1 ) of the page to activate.
         * @example
         * setActiveTab( 1 );
         */
        static _setActiveSettingsTab( index ) {
            let tab_names = [ 'dc-plugin-settings-tab', 'dc-database-settings-tab', 'dc-security-settings-tab' ];
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
            case 2:
                $( '#dc-security-settings-btn' ).addClass( 'active' );
                $( '#dc-security-settings-tab' ).css( 'display', 'block' );
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
        static _setActiveExchangeTab( index ) {
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
         * @desc Generates a nonce according to Discord's internal EPOCH. ( 14200704e5 )
         * @return {string} The string representation of the integer nonce.
         */
        static _getNonce() {
            return _cachedModules.NonceGenerator.fromTimestamp( Date.now() );
        }

        /**
         * @private
         * @desc Returns the name of the plugin file expected on the disk.
         * @returns {string}
         * @example
         * console.log( discordCrypt._getPluginName() );
         * // "discordCrypt.plugin.js"
         */
        static _getPluginName() {
            return 'discordCrypt.plugin.js';
        }

        /**
         * @private
         * @desc Check if the plugin is named correctly by attempting to open the plugin file in the BetterDiscord
         *      plugin path.
         * @returns {boolean}
         * @example
         * console.log( _discordCrypt._validPluginName() );
         * // False
         */
        static _validPluginName() {
            return require( 'fs' )
                .existsSync( require( 'path' )
                    .join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() ) );
        }

        /**
         * @private
         * @desc Returns the platform-specific path to BetterDiscord's plugin directory.
         * @returns {string} The expected path ( which may not exist ) to BetterDiscord's plugin directory.
         * @example
         * console.log( _discordCrypt._getPluginsPath() );
         * // "C:\Users\John Doe\AppData\Local/BetterDiscord/plugins"
         */
        static _getPluginsPath() {
            const process = require( 'process' );
            return `${process.platform === 'win32' ?
                process.env.APPDATA :
                process.platform === 'darwin' ?
                    process.env.HOME + '/Library/Preferences' :
                    process.env.HOME + '/.config'}/BetterDiscord/plugins/`;
        }

        /**
         * @private
         * @desc Checks if the plugin should ignore auto-updates.
         *      Usually in a developer environment, a simple symlink is ( or should be ) used to link the current build
         *      file to the plugin path allowing faster deployment.
         * @param {string} version Version string of the plugin to include in the check.
         * @return {boolean} Returns false if the plugin should auto-update.
         */
        static _shouldIgnoreUpdates( version ) {
            const fs = require( 'fs' );
            const path = require( 'path' );
            const plugin_file = path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );

            return fs.existsSync( plugin_file ) &&
            ( fs.lstatSync( plugin_file ).isSymbolicLink() || version.indexOf( '-debug' ) !== -1 );
        }

        /**
         * @private
         * @desc Checks the update server for an encrypted update.
         * @param {UpdateCallback} on_update_callback Callback to execute when an update is found.
         * @param {Array<UpdateInfo>} [blacklisted_updates] Optional list of blacklisted updates to ignore.
         * @returns {boolean}
         * @example
         * _checkForUpdate( ( info ) => {
         *      if( !info ) {
         *          console.log( 'No update available.' );
         *          return;
         *      }
         *      console.log( `New Update Available: #${info.hash} - v${info.version}` );
         *      console.log( `Signature is: ${info.valid ? valid' : 'invalid'}!` );
         *      console.log( `Changelog:\n${info.changelog}` );
         * } );
         */
        static _checkForUpdate( on_update_callback, blacklisted_updates ) {
            /* Update URL and request method. */
            const base_url = 'https://gitlab.com/leogx9r/discordCrypt/raw/master';
            const update_url = `${base_url}/build/${_discordCrypt._getPluginName()}`;
            const changelog_url = `${base_url}/src/CHANGELOG`;
            const signature_url = `${update_url}.sig`;

            /**
             * @desc Local update information.
             * @type {UpdateInfo}
             */
            let updateInfo = {
                version: '',
                payload: '',
                valid: false,
                hash: '',
                signature: '',
                changelog: ''
            };

            /* Make sure the callback is a function. */
            if ( typeof on_update_callback !== 'function' )
                return false;

            /* Perform the request. */
            try {
                /* Download the update. */
                _discordCrypt.__getRequest( update_url, ( statusCode, errorString, data ) => {
                    /* Make sure no error occurred. */
                    if ( statusCode !== 200 ) {
                        /* Log the error accordingly. */
                        switch ( statusCode ) {
                        case 404:
                            _discordCrypt.log( 'Update URL is broken.', 'error' );
                            break;
                        case 403:
                            _discordCrypt.log( 'Forbidden request when checking for updates.', 'error' );
                            break;
                        default:
                            _discordCrypt.log( `Error while fetching update: ${statusCode}:${errorString}`, 'error' );
                            break;
                        }

                        on_update_callback( null );
                        return false;
                    }

                    /* Get the local file. */
                    let localFile = '//META{"name":"discordCrypt"}*//\n';
                    try {
                        localFile = require( 'fs' ).readFileSync(
                            require( 'path' ).join(
                                _discordCrypt._getPluginsPath(),
                                _discordCrypt._getPluginName()
                            )
                        ).toString().replace( '\r', '' );
                    }
                    catch ( e ) {
                        _discordCrypt.log(
                            'Plugin file could not be locally read. Assuming testing version ...',
                            'warn'
                        );
                    }

                    /* Check the first line which contains the metadata to make sure that they're equal. */
                    if ( data.split( '\n' )[ 0 ] !== localFile.split( '\n' )[ 0 ] ) {
                        _discordCrypt.log(
                            'Plugin metadata is missing from either the local or update file.',
                            'error'
                        );

                        on_update_callback( null );
                        return false;
                    }

                    /* Read the current hash of the plugin and compare them.. */
                    let currentHash = _discordCrypt.__sha256( localFile.replace( '\r', '' ), true );
                    updateInfo.hash = _discordCrypt.__sha256( data.replace( '\r', '' ), true );

                    /* If the hash equals the retrieved one, no update is needed. */
                    if ( updateInfo.hash === currentHash ) {
                        _discordCrypt.log( `No Update Needed - #${updateInfo.hash.slice( 0, 16 )}` );

                        on_update_callback( null );
                        return true;
                    }

                    /* Check if the hash matches a blacklisted update. */
                    if(
                        blacklisted_updates &&
                        blacklisted_updates.length &&
                        blacklisted_updates.filter( e => e && e.hash === updateInfo.hash ).length !== 0
                    ) {
                        _discordCrypt.log( `Ignoring update - #${updateInfo.hash.slice( 0, 16 )}` );

                        on_update_callback( null );
                        return true;
                    }

                    /* Try parsing a version number. */
                    try {
                        updateInfo.version = data
                            .match( /((["'])(\d+\.)(\d+\.)(\*|\d+)(["']))/gi )
                            .toString()
                            .replace( /(['|"]*['|"])/g, '' );
                    }
                    catch ( e ) {
                        updateInfo.version = '?.?.?';
                        _discordCrypt.log( 'Failed to locate the version number in the update ...', 'warn' );
                    }

                    /* Basically the finally step - resolve the changelog & call the callback function. */
                    let tryResolveChangelog = ( valid_signature ) => {
                        /* Store the validity. */
                        updateInfo.valid = valid_signature;

                        /* Now get the changelog. */
                        try {
                            /* Fetch the changelog from the URL. */
                            _discordCrypt.__getRequest(
                                changelog_url,
                                ( statusCode, errorString, changelog ) => {
                                    updateInfo.changelog = statusCode == 200 ? changelog : '';

                                    /* Perform the callback. */
                                    on_update_callback( updateInfo );
                                }
                            );
                        }
                        catch ( e ) {
                            _discordCrypt.log( 'Error fetching the changelog.', 'warn' );

                            /* Perform the callback without a changelog. */
                            updateInfo.changelog = '';
                            on_update_callback( updateInfo );
                        }
                    };

                    /* Store the update. */
                    updateInfo.payload = data;

                    /* Try validating the signature. */
                    try {
                        /* Fetch the detached signature. */
                        _discordCrypt.__getRequest( signature_url, ( statusCode, errorString, detached_sig ) => {
                            /* Store the signature. */
                            updateInfo.signature = detached_sig;

                            /* Validate the signature then continue. */
                            let r = _discordCrypt.__validatePGPSignature(
                                updateInfo.payload,
                                updateInfo.signature,
                                _discordCrypt.__zlibDecompress( _signingKey )
                            );

                            /* This returns a Promise if valid or false if invalid. */
                            if( r )
                                r.then( ( valid_signature ) => tryResolveChangelog( valid_signature ) );
                            else
                                tryResolveChangelog( false );
                        } );
                    }
                    catch( e ) {
                        _discordCrypt.log( `Unable to validate the update signature: ${e}`, 'warn' );

                        /* Resolve the changelog anyway even without a valid signature. */
                        tryResolveChangelog( false );
                    }

                    return true;
                } );
            }
            catch ( ex ) {
                /* Handle failure. */
                _discordCrypt.log( `Error while retrieving update: ${ex.toString()}`, 'warn' );
                return false;
            }

            return true;
        }

        /**
         * @private
         * @description Returns the current message ID used by Discord.
         * @returns {string | undefined}
         * @example
         * console.log( _discordCrypt._getChannelId() );
         * // "414714693498014617"
         */
        static _getChannelId() {
            return window.location.pathname.split( '/' ).pop();
        }

        /**
         * @private
         * @desc Creates a password object using a primary and secondary password.
         * @param {string} primary_password The primary password.
         * @param {string} secondary_password The secondary password.
         * @returns {ChannelPassword} Object containing the two passwords.
         * console.log( _discordCrypt._createPassword( 'Hello', 'World' ) );
         * // Object {primary: "Hello", secondary: "World"}
         */
        static _createPassword( primary_password, secondary_password ) {
            return { primary: primary_password, secondary: secondary_password };
        }

        /**
         * @private
         * @desc Returns functions to locate exported webpack modules.
         * @returns {WebpackModuleSearcher}
         */
        static _getWebpackModuleSearcher() {
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
                    _discordCrypt.log( "Couldn't find module in existing cache. Loading all modules.", 'warn' );

                    for ( let i = 0; i < req.m.length; ++i ) {
                        try {
                            let m = req( i );
                            if ( m && m.__esModule && m.default && filter( m.default ) )
                                return m.default;
                            if ( m && filter( m ) )
                                return m;
                        }
                        catch ( e ) {
                            _discordCrypt.log( `Could not load module index ${i} ...`, 'warn' );
                        }
                    }

                    _discordCrypt.log( 'Cannot find Webpack module.', 'warn' );
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
                find(
                    module => protoNames.every( proto => module.prototype && module.prototype[ proto ] ),
                    force_load
                );

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
                find(
                    module =>
                        module[ '_dispatchToken' ] &&
                        typeof module[ '_dispatchToken' ] === 'string' &&
                        module[ '_dispatchToken' ] === `ID_${token}` &&
                        module[ '_actionHandlers' ],
                    force_load
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
         * @experimental
         * @private
         * @desc Dumps all function callback handlers with their names, IDs and function prototypes. [ Debug Function ]
         * @param {boolean} [dump_actions] Whether to dump action handlers.
         * @returns {Array} Returns an array of all IDs and identifier callbacks.
         */
        static _dumpWebpackModuleCallbacks( dump_actions = true ) {
            const ignored = [
                '_dependencies',
                '_isInitialized',
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

            /* Create the dumping array. */
            let dump = [], i = 0;

            /* Iterate over let's say 1000 possible modules ? */
            _discordCrypt._getWebpackModuleSearcher().find( ( module ) => {
                if( !module[ '__esModule' ] )
                    return false;

                /* Create an entry in the array. */
                dump[ i ] = {};

                /* Loop over every property in the module. */
                for( let prop in module ) {
                    /* Skip ignored. */
                    if( ignored.indexOf( prop ) !== -1 )
                        continue;

                    /* Dump action handlers. */
                    if( [ '_actionHandlers', '_dispatchHandlers', '_changeCallbacks' ].indexOf( prop ) !== -1 ) {
                        /* Skip if not required. */
                        if( !dump_actions )
                            continue;

                        dump[ i ][ prop ] = {};

                        /* Loop over every property name in the action handler. */
                        for ( let action in module[ prop ] ) {

                            /* Quick sanity check. */
                            if ( !action.length || !module._actionHandlers.hasOwnProperty( action ) )
                                continue;

                            try{
                                /* Assign the module property name and it's basic prototype. */
                                dump[ i ][ prop ][ action ] =
                                    module[ prop ][ action ].prototype.constructor.toString().split( '{' )[ 0 ];
                            }
                            catch( e ) {
                                dump[ i ][ prop ] = 'N/A';
                            }
                        }
                    }
                    else {
                        try{
                            /* Add the actual property name and its prototype. */
                            dump[ i ][ prop ] = module[ prop ].toString().split( '{' )[ 0 ];
                        }
                        catch( e ) {
                            dump[ i ][ prop ] = 'N/A';
                        }
                    }
                }

                i++;
                return false;
            } );

            /* Return any found module handlers. */
            return dump;
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
        static _getElementReactOwner(
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
            const getOwnerReactInstance = e => e[ Object.keys( e )
                .find( k => k.startsWith( "__reactInternalInstance" ) ) ];
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
         * @private
         * @desc Returns the channel properties for the currently viewed channel or null.
         * @return {object}
         */
        static _getChannelProps() {
            /* Blacklisted IDs that don't have actual properties. */
            const blacklisted_channel_props = [
                '@me',
                'activity'
            ];

            /* Skip blacklisted channels. */
            if( blacklisted_channel_props.indexOf( _discordCrypt._getChannelId() ) === -1 ) {
                let elementOwner = _discordCrypt._getElementReactOwner( $( 'form' )[ 0 ] );

                /* Ensure the properties exist. */
                if ( elementOwner[ 'props' ] && elementOwner.props[ 'channel' ] )
                    /* Return the result. */
                    return elementOwner.props.channel;
            }

            /* Return nothing for invalid channels. */
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
        static _editMessage( channel_id, message_id, content, cached_modules ) {
            /* Edit the message internally. */
            cached_modules.MessageController._editMessage( channel_id, message_id, { content: content } );
        }

        /**
         * @private
         * @desc Delete the message from the channel indicated.
         * @param {string} channel_id The channel's identifier that the message is located in.
         * @param {string} message_id The message's identifier to delete.
         * @param {CachedModules} cached_modules The internally cached module objects.
         */
        static _deleteMessage( channel_id, message_id, cached_modules ) {
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
         * @param {Array<TimedMessage>} [timed_messages] Array containing timed messages to add this sent message to.
         * @param {int} [expire_time_minutes] The amount of minutes till this message is to be deleted.
         */
        static _dispatchMessage(
            as_embed,
            main_message,
            message_header,
            message_footer,
            embedded_color = 0x551A8B,
            message_content = '',
            channel_id = undefined,
            timed_messages = undefined,
            expire_time_minutes = 0
        ) {
            let mention_everyone = false;

            /* Parse the message content to the required format if applicable.. */
            if ( typeof message_content === 'string' && message_content.length ) {
                /* Sanity check. */
                if ( _cachedModules.MessageCreator === null ) {
                    _discordCrypt.log( 'Could not locate the MessageCreator module!', 'error' );
                    return;
                }

                try {
                    /* Parse the message. */
                    message_content = _cachedModules
                        .MessageCreator
                        .parse( _discordCrypt._getChannelProps(), message_content ).content;

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
            let _channel = channel_id !== undefined ? channel_id : _discordCrypt._getChannelId();

            /* Handles returns for messages. */
            const onDispatchResponse = ( r ) => {
                /* Check if an error occurred and inform Clyde bot about it. */
                if ( !r.ok ) {
                    /* Perform Clyde dispatch if necessary. */
                    if (
                        r.status >= 400 &&
                        r.status < 500 &&
                        r.body &&
                        !_cachedModules.MessageController.sendClydeError( _channel, r.body.code )
                    ) {
                        /* Log the error in case we can't manually dispatch the error. */
                        _discordCrypt.log( `Error sending message: ${r.status}`, 'error' );

                        /* Sanity check. */
                        if ( _cachedModules.MessageDispatcher === null || _cachedModules.GlobalTypes === null ) {
                            _discordCrypt.log( 'Could not locate the MessageDispatcher module!', 'error' );
                            return;
                        }

                        _cachedModules.MessageDispatcher.dispatch( {
                            type: _cachedModules.GlobalTypes.ActionTypes.MESSAGE_SEND_FAILED,
                            messageId: r.body.id,
                            channelId: _channel
                        } );
                    }
                }
                else {
                    /* Receive the message normally. */
                    _cachedModules.MessageController.receiveMessage( _channel, r.body );

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
                /* Create the message embed object and add it to the queue. */
                _cachedModules.MessageQueue.enqueue(
                    {
                        type: 'send',
                        message: {
                            channelId: _channel,
                            nonce: _discordCrypt._getNonce(),
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
                                    icon_url:
                                        'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/images/encode-logo.png',
                                    url: 'https://discord.me/discordCrypt'
                                },
                                footer: {
                                    text: message_footer || 'discordCrypt',
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

                    /* Create the message object and dispatch it to the queue. */
                    _cachedModules.MessageQueue.enqueue(
                        {
                            type: 'send',
                            message: {
                                channelId: _channel,
                                nonce: _discordCrypt._getNonce(),
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
         * _injectCSS( 'my-css', 'p { font-size: 32px; }' );
         */
        static _injectCSS( id, css ) {
            /* Inject into the header tag. */
            $( "head" )
                .append( $( "<style>", { id: id.replace( /^[^a-z]+|[^\w-]+/gi, "" ), html: css } ) )
        }

        /**
         * @private
         * @desc Clears an injected element via its ID tag.
         * @param {string} id The HTML ID string used to identify this CSS style segment.
         * @example
         * _clearCSS( 'my-css' );
         */
        static _clearCSS( id ) {
            /* Make sure the ID is a valid string. */
            if ( !id || typeof id !== 'string' || !id.length )
                return;

            /* Remove the element. */
            $( `#${id.replace( /^[^a-z]+|[^\w-]+/gi, "" )}` ).remove();
        }

        /**
         * @private
         * @author samogot
         * @desc This function monkey-patches a method on an object.
         *      The patching callback may be run before, after or instead of target method.
         *      Be careful when monkey-patching. Think not only about original functionality of target method and your
         *      changes, but also about developers of other plugins, who may also patch this method before or after you.
         *      Try to change target method behaviour as little as possible, and avoid changing method signatures.
         *
         *      By default, this function logs to the console whenever a method is patched or unpatched in order to aid
         *      debugging by you and other developers, but these messages may be suppressed with the `silent` option.
         *
         *      Display name of patched method is changed, so you can see if a function has been patched
         *      ( and how many times ) while debugging or in the stack trace. Also, patched methods have property
         *      `__monkeyPatched` set to `true`, in case you want to check something programmatically.
         *
         * @param {object} what Object to be patched.
         *      You can can also pass class prototypes to patch all class instances.
         *      If you are patching prototype of react component you may also need.
         * @param {string} methodName The name of the target message to be patched.
         * @param {object} options Options object. You should provide at least one of `before`, `after` or `instead`
         *      parameters. Other parameters are optional.
         * @param {PatchCallback} options.before Callback that will be called before original target
         *      method call. You can modify arguments here, so it will be passed to original method.
         *      Can be combined with `after`.
         * @param {PatchCallback} options.after Callback that will be called after original
         *      target method call. You can modify return value here, so it will be passed to external code which calls
         *      target method. Can be combined with `before`.
         * @param {PatchCallback} options.instead Callback that will be called instead of original target method call.
         *      You can get access to original method using `originalMethod` parameter if you want to call it,
         *      but you do not have to. Can't be combined with `before` and `after`.
         * @param {boolean} [options.once=false] Set to `true` if you want to automatically unpatch method after
         *      first call.
         * @param {boolean} [options.silent=false] Set to `true` if you want to suppress log messages about
         *      patching and unpatching. Useful to avoid clogging the console in case of frequent conditional
         *      patching/unpatching, for example from another monkeyPatch callback.
         * @param {string} [options.displayName] You can provide meaningful name for class/object provided in
         *      `what` param for logging purposes. By default, this function will try to determine name automatically.
         * @param {boolean} [options.forcePatch=true] Set to `true` to patch even if the function doesn't exist.
         *      ( Adds noop function in place. )
         * @return {function()} Function with no arguments and no return value that should be
         *      called to cancel this patch. You should save and run it when your plugin is stopped.
         */
        static _monkeyPatch( what, methodName, options ) {
            /**
             * Wraps the method in a `try..catch` block.
             * @param {function} method - method to wrap
             * @param {string} description - description of method
             * @returns {function} wrapped version of method
             */
            const suppressErrors = ( method, description ) => ( ... params ) => {
                try {
                    return method( ... params );
                }
                catch ( e ) {
                    _discordCrypt.log( `Error while '${description}'`, 'error' );
                }
                return undefined;
            };

            /* Grab options. */
            const { before, after, instead, once = false, silent = true, forcePatch = true } = options;

            /* Determine the display name for logging. */
            const displayName = options.displayName || what.displayName || what.name ||
                what.constructor.displayName || what.constructor.name;

            /* Log if required. */
            if ( !silent )
                _discordCrypt.log( `Patching ${methodName} ...` );

            /* Backup the original method for unpatching or restoring. */
            let origMethod = what[ methodName ];

            /* If a method can't be found, handle appropriately based on if forcing patches. */
            if ( !origMethod ) {
                if ( !forcePatch ) {
                    /* Log and bail out. */
                    _discordCrypt.log(
                        `Can't find non-existent method '${displayName}.${methodName}' to patch.`,
                        'error'
                    );
                    return () => {
                        /* Ignore. */
                    };
                }
                else {
                    /* Assign empty functions. */
                    what[ methodName ] = function() {
                        /* Ignore. */
                    };
                    origMethod = function() {
                        /* Ignore. */
                    };
                }
            }

            /* Create a callback that can cancel the patch. */
            const cancel = () => {
                /* Log if appropriate. */
                if ( !silent )
                    _discordCrypt.log( `Removing patched method: '${displayName}.${methodName}' ...` );

                /* Restore the original method thus removing the patch. */
                what[ methodName ] = origMethod;
            };

            /* Apply a wrapper function that calls the callbacks based on the options. */
            what[ methodName ] = function() {
                /**
                 * @desc Contains the local patch state for this function.
                 * @type {PatchData}
                 */
                const data = {
                    thisObject: this,
                    methodArguments: arguments,
                    cancelPatch: cancel,
                    originalMethod: origMethod,
                    callOriginalMethod: () =>
                        data.returnValue = data.originalMethod.apply( data.thisObject, data.methodArguments )
                };

                /* Call the callback instead of the method with the defined return value if any. */
                if ( instead ) {
                    const tempRet = suppressErrors(
                        instead,
                        `calling override instead of original for '${what[ methodName ].displayName}'`
                    )( data );

                    if ( tempRet !== undefined )
                        data.returnValue = tempRet;
                }
                else {
                    /* Handle execution before the method call. */
                    if ( before )
                        suppressErrors(
                            before,
                            `calling override before '${what[ methodName ].displayName}'`
                        )( data );

                    /* Actually call the original method. */
                    data.callOriginalMethod();

                    /* Handle execution after the method call. */
                    if ( after )
                        suppressErrors(
                            after,
                            `calling override after '${what[ methodName ].displayName}'`
                        )( data );
                }

                /* If this function hook is just being executed once, unhook it now. */
                if ( once )
                    cancel();

                return data.returnValue;
            };

            /* Make sure the method is marked as patched. */
            what[ methodName ].__monkeyPatched = true;
            what[ methodName ].displayName = `patched ${what[ methodName ].displayName || methodName}`;

            /* Save the unhook method to the object. */
            what[ methodName ].unpatch = cancel;

            /* Return the callback necessary for cancelling. */
            return cancel;
        }

        /**
         * @private
         * @desc Hooks a dispatcher from Discord's internals.
         * @param {object} dispatcher The action dispatcher containing an array of _actionHandlers.
         * @param {string} method_name The name of the method to hook.
         * @param {string} options The type of hook to apply. [ 'before', 'after', 'instead', 'revert' ]
         * @param {boolean} [options.once=false] Set to `true` if you want to automatically unhook
         *      method after first call.
         * @param {boolean} [options.silent=false] Set to `true` if you want to suppress log messages about patching and
         *      unhooking. Useful to avoid clogging the console in case of frequent conditional hooking/unhooking, for
         *      example from another monkeyPatch callback.
         */
        static _hookDispatcher( dispatcher, method_name, options ) {
            /* Hook the dispatcher. */
            let fn = _discordCrypt._monkeyPatch( dispatcher._actionHandlers, method_name, options );

            /* Add it to the existing list of cancel-callbacks. */
            _stopCallbacks.push( fn );

            /* Return the callback. */
            return fn;
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
                console[ method ](
                    `%c[DiscordCrypt]%c - ${message}`,
                    "color: #7f007f; font-weight: bold; text-shadow: 0 0 1px #f00, 0 0 2px #f0f, 0 0 3px #00f;",
                    ""
                );
            }
            catch ( ex ) {
                console.error( '[DiscordCrypt] - Error logging message ...' );
            }
        }

        /* ========================================================= */

        /* ======================= UTILITIES ======================= */

        /**
         * @private
         * @desc Checks if the input password is at least 8 characters long,
         *      is alpha-numeric with both upper and lowercase as well as contains at least one symbol.
         *      Alternatively checks if the input is at least 64 characters to bypass the above check.
         *      Alerts the user if both conditions do not pass.
         * @param {string} input The input password to validate.
         * @return {boolean} Returns true if the password is valid.
         */
        static __validatePasswordRequisites( input ) {
            if(
                input.length < 64 &&
                !( new RegExp( /^(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W).*$/g ) ).test( input )
            ) {
                global.smalltalk.alert(
                    'Invalid Password Input',
                    'Your password <b>must be at least 8 characters</b> long and <u>must</u> contain ' +
                    'a combination of alpha-numeric characters both uppercase and lowercase ( A-Z, a-z, 0-9 ) ' +
                    'as well as at least one symbol <b>OR</b> be greater than 64 characters for the best security.' +
                    '<br/><br/><br/>' +
                    'Please enter a password meeting these requirements.<br/>' +
                    'We recommend you use a password manager like KeePassX or KeePassXC to easily store these.'
                );
                return false;
            }

            return true;
        }

        /**
         * @public
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
         *      local_pub_key = Buffer.from(
         *          "e77ef936546d73dc5a1c25c8267df649c935168f24827267b1328fd22789eca9", 'hex'
         *      );
         *
         *      remote_id = Buffer.from( "2c08a0666e937d115f8b05c82db8a6d0", 'hex' );
         *      remote_pub_key = Buffer.from(
         *          "f2f10dc9d0770e3be28298c2d4ab7a856c92bafa99ff7377ec8cd538bd9481ae", 'hex'
         *      );
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
                    input = Buffer.from( _discordCrypt.__sha256( Buffer.concat( [ input, key ] ), true ), 'hex' );
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
            if( typeof global === 'undefined' || !global.openpgp )
                return false;

            let options = {
                message: global.openpgp.message.fromText( message ),
                signature: global.openpgp.signature.readArmored( signature ),
                publicKeys: global.openpgp.key.readArmored( public_key ).keys
            };

            return global.openpgp.verify( options ).then( ( validity ) => validity.signatures[ 0 ].valid );
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
         * @desc Loads all compiled _libraries as needed.
         * @param {LibraryDefinition} libraries A list of all _libraries to load.
         */
        static __loadLibraries( libraries ) {
            const vm = require( 'vm' );

            /* Inject all compiled _libraries based on if they're needed */
            for ( let name in libraries ) {
                let libInfo = libraries[ name ];

                /* Browser code requires a window object to be defined. */
                if ( libInfo.requiresBrowser && typeof window === 'undefined' ) {
                    _discordCrypt.log( `Skipping loading of browser-required plugin: ${name} ...`, 'warn' );
                    continue;
                }

                /* Decompress the Base64 code. */
                let code = _discordCrypt.__zlibDecompress( libInfo.code );

                /* Determine how to run this. */
                if ( libInfo.requiresBrowser || libInfo.requiresNode ) {
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
                msg = _discordCrypt.__substituteMessage( msg );

                /* Decode the message to raw bytes. */
                msg = Buffer.from( msg, 'hex' );

                /* Sanity check. */
                if ( !_discordCrypt.__isValidExchangeAlgorithm( msg[ 0 ] ) )
                    return null;

                /* Create a fingerprint for the blob. */
                output[ 'fingerprint' ] = _discordCrypt.__sha256( msg, true );

                /* Buffer[0] contains the algorithm type. Reverse it. */
                output[ 'bit_length' ] = _discordCrypt.__indexToAlgorithmBitLength( msg[ 0 ] );
                output[ 'algorithm' ] = _discordCrypt.__indexToExchangeAlgorithmString( msg[ 0 ] )
                    .split( '-' )[ 0 ].toLowerCase();

                return output;
            }
            catch ( e ) {
                return null;
            }
        }

        /**
         * @public
         * @desc Smartly splits the input text into chunks according to the specified length while
         *      attempting to preserve word spaces unless they exceed the limit.
         * @param {string} input_string The input string.
         * @param {int} max_length The maximum length of the string before splitting.
         * @returns {Array} An array of split strings.
         * @private
         */
        static __splitStringChunks( input_string, max_length ) {
            /* Sanity check. */
            if ( !max_length || max_length <= 1 )
                return input_string;

            /* Split the string into words. */
            const words = input_string.split( ' ' );

            /* Create vars for storing the result, current string and first-word flag. */
            let ret = [], current = '', first = true;

            /* Iterate over all words. */
            words.forEach( word => {
                /* Check if the current string would overflow if the word was added. */
                if( ( current.length + word.length ) > max_length && current.length ) {
                    /* Insert the string into the array and reset it. */
                    ret.push( current );

                    /* Reset the sentence. */
                    current = '';
                }

                /* Add the current word to the sentence without a space only if it's the first word. */
                if( first ) {
                    current += word;
                    first = false;
                }
                else
                    current += ` ${word}`;

                /* If the current sentence is longer than the maximum, split it and add to the result repeatedly. */
                while( current.length > max_length ) {
                    /* Add it to the array. */
                    ret.push( current.substr( 0, max_length ) );

                    /* Get the remaining. */
                    current = current.substr( max_length );
                }
            } );

            /* If the current sentence has something, add it to the array. */
            if( current.length )
                ret.push( current );

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
         * @desc Extracts all tags from the given message and optionally removes any tagged discriminators.
         * @param {string} message The input message to extract all tags from.
         * @param {object} channelProps The properties of the current channel used for parsing.
         * @returns {UserTags}
         */
        static __extractTags( message, channelProps ) {
            let split_msg = message.split( ' ' );
            let cleaned_tags = '', cleaned_msg = '', tmp_tag;
            let user_tags = [];

            /* Iterate over each segment and check for usernames. */
            for ( let i = 0, k = 0; i < split_msg.length; i++ ) {
                /* Check for normal user names. */
                if ( this.__isValidUserName( split_msg[ i ] ) ) {
                    user_tags[ k++ ] = split_msg[ i ];
                    cleaned_msg += `${split_msg[ i ].split( '#' )[ 0 ]} `;
                }
                /* Check for parsed user IDs. */
                else if ( ( /(<@[!]*[0-9]{14,22}>)/gm ).test( split_msg[ i ] ) ) {
                    user_tags[ k++ ] = split_msg[ i ];

                    /* Convert the tag back to human-readable form if a valid channel props was passed. */
                    tmp_tag = channelProps ?
                        _cachedModules.MessageCreator.unparse( split_msg[ i ], channelProps ) :
                        split_msg[ i ];
                    cleaned_msg += `${tmp_tag.split( '#' )[ 0 ]} `;
                }
                /* Check for @here or @everyone. */
                else if ( [ '@everyone', '@here', '@me' ].indexOf( split_msg[ i ] ) !== -1 ) {
                    user_tags[ k++ ] = split_msg[ i ];
                    cleaned_msg += `${split_msg[ i ]} `;
                }
                /* Check for parsed channel tags. */
                else if ( ( /(<#[0-9]{14,22}>)/gm ).test( split_msg[ i ] ) ) {
                    user_tags[ k++ ] = split_msg[ i ];

                    /* Convert the channel tag back to human-readable form if a valid channel props was passed. */
                    cleaned_msg += `${channelProps ?
                        _cachedModules.MessageCreator.unparse( split_msg[ i ], channelProps ) :
                        split_msg[ i ]} `;
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
                inline_block_expr = new RegExp( /^(`+)\s*([\s\S]*?[^`])\s*\1(?!`)/g ),
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
         * @desc Detects and extracts all formatted emojis in a message.
         *      Basically, all emojis are formatted as follows:
         *          <:##EMOJI NAME##:##SNOWFLAKE##>
         *
         *      Animated emojis have the format:
         *          <a:##EMOJI NAME##:##SNOWFLAKE##>
         *
         *      This translates to a valid URI always:
         *          https://cdn.discordapp.com/emojis/##SNOWFLAKE##.png
         *      Or:
         *          https://cdn.discordapp.com/emojis/##SNOWFLAKE##.gif
         *
         *      This means it's a simple matter of extracting these from a message and building an image embed.
         *          <img src="##URI##" class="##EMOJI CLASS##" alt=":#EMOJI NAME##:">
         * @param {string} message The message to extract all emojis from.
         * @param {boolean} as_html Whether to interpret anchor brackets as HTML.
         * @return {Array<EmojiDescriptor>} Returns an array of EmojiDescriptor objects.
         */
        static __extractEmojis( message, as_html = false ) {
            let _emojis = [], _matched;

            /* Execute the regex for finding emojis on the message. */
            let emoji_expr = new RegExp(
                as_html ?
                    /((&lt;[a]*)(:(?![\n])[-\w]+:)([0-9]{14,22})(&gt;))/gm :
                    /((<[a]*)(:(?![\n])[-\w]+:)([0-9]{14,22})(>))/gm
            );

            /* Iterate over each matched emoji. */
            while ( ( _matched = emoji_expr.exec( message ) ) ) {
                /* Insert the emoji's snowflake and name. */
                _emojis.push( {
                    animated: _matched[ 2 ].indexOf( 'a' ) !== -1,
                    formatted: _matched[ 0 ],
                    name: _matched[ 3 ],
                    snowflake: _matched[ 4 ]
                } );
            }

            /* Return the results. */
            return _emojis;
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
                let _extracted = _discordCrypt.__extractCodeBlocks( message );

                /* Wrap the message normally. */
                if ( !_extracted.length )
                    return {
                        code: false,
                        html: message
                    };

                /* Loop over each expanded code block. */
                for ( let i = 0; i < _extracted.length; i++ ) {
                    let lang = _extracted[ i ].language,
                        raw = _extracted[ i ].raw_code;

                    /* Inline code blocks get styled differently. */
                    if ( lang !== 'inline' ) {
                        /* For multiple line blocks, new lines are also captured from above. Remove them. */
                        if( raw[ 0 ] === '\n' )
                            raw = raw.substr( 1 );
                        if( raw[ raw.length - 1 ] === '\n' )
                            raw = raw.substr( 0, raw.length - 1 );

                        /* Build a <pre><code></code></pre> element for HLJS to work on. */
                        let code_block = $( '<pre>' ).addClass( lang ).append( $( '<code>' ).html( raw ) );

                        /* Highlight this block. */
                        _cachedModules.HighlightJS.highlightBlock( code_block[ 0 ] );

                        /* Replace the code with an HTML formatted code block. */
                        message = message.split( _extracted[ i ].captured_block ).join( code_block[ 0 ].outerHTML );
                    }
                    else {
                        /* Split the HTML message according to the inline markdown code block. */
                        message = message.split( _extracted[ i ].captured_block );

                        /* Replace the data with a inline code class. */
                        message = message.join( `<code class="inline">${raw}</code>` );
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
                /* Split message into array for easier parsing */
                message = message.split( ' ' );

                let containsURL = false;

                /* Simple detection and replacement */
                for ( let i = 0; i < message.length; i++ ) {
                    try {

                        /* Creates URL object of every chunk in the message */
                        let url = new URL( message[ i ] );

                        /* Only allows https and http protocols */
                        if( url.protocol === 'https:' || url.protocol === 'http:' ) {
                            containsURL = true;

                            /* If this is an Up1 host, we can directly embed it. Obviously don't embed deletion links.*/
                            if (
                                embed_link_prefix !== undefined &&
                                message[ i ].startsWith( `${embed_link_prefix}/#` ) &&
                                message[ i ].indexOf( 'del?ident=' ) === -1
                            )
                                message[ i ] =
                                    `<a target="_blank" rel="noopener noreferrer" href="${url.href}">${url.href}</a>
                                    <iframe src=${url.href} width="100%" height="400px"></iframe><br/><br/>`;

                            else
                                /* Replaces the inputted URL with a formatted one */
                                message[ i ] =
                                    `<a target="_blank" rel="noopener noreferrer" href="${url.href}">${url.href}</a>`;
                        }

                    }
                    /* If the object creation fails, message chunk wasn't a valid URL */
                    catch( e ) {
                        /* Ignore. */
                    }
                }

                /* Rejoin the message array back to normal */
                message = message.join( ' ' );

                /* Wrap the message in span tags. */
                if( containsURL )
                    return {
                        url: true,
                        html: `<span>${message}</span>`
                    };

                /* If the message didn't contain a URL return normal message */
                else return {
                    url: false,
                    html: message
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
         * @desc Extracts emojis from a message and formats them as IMG embeds.
         * @param {string} message The message to format.
         * @param {string} emoji_class The class used for constructing the emoji image.
         * @param {Object} emoji_ctx The internal context for parsing emoji surrogates.
         * @return {EmojiInfo} Returns whether the message contains Emojis and the formatted HTML.
         */
        static __buildEmojiMessage( message, emoji_class, emoji_ctx ) {
            /* Get all emojis in the message. */
            let emojis = _discordCrypt.__extractEmojis( message, true );

            /* Parse any default-emojis. */
            typeof emoji_ctx !== 'undefined' && emoji_ctx.forEach( ( item ) => {
                if( !item.surrogates.length )
                    return;

                message = message
                    .split( item.surrogates )
                    .join(
                        '<span class="dc-tooltip dc-tooltip-delayed">' +
                        `<img src="${item.defaultUrl}" class="${emoji_class}" alt=":${item.names[ 0 ]}:">` +
                        `<span class="dc-tooltip-text" style="font-size: 12px">:${item.names[ 0 ]}:</span>` +
                        '</span>'
                    );
            } );

            /* Return the default if no emojis are defined. */
            if( !emojis.length ) {
                return {
                    emoji: false,
                    html: message
                }
            }

            /* Loop over every emoji and format them in the message.. */
            for( let i = 0; i < emojis.length; i++ ) {
                let e = emojis[ i ];

                /* Get the URI for this. */
                let URI = `https://cdn.discordapp.com/emojis/${e.snowflake}.${e.animated ? 'gif' : 'png'}`;

                /* Replace the message with a link. */
                message = message
                    .split( emojis[ i ].formatted )
                    .join(
                        '<span class="dc-tooltip dc-tooltip-delayed">' +
                        `<img src="${URI}" class="${emoji_class}" alt="${e.name}">` +
                        `<span class="dc-tooltip-text" style="font-size: 12px">${e.name}</span>` +
                        '</span>'
                    );
            }

            /* Return the result. */
            return {
                emoji: true,
                html: message
            }
        }

        /**
         * @public
         * @desc Returns a string, Buffer() or Array() as a buffered object.
         * @param {string|Buffer|Array} input The input variable.
         * @param {boolean|undefined} [is_input_hex] If set to true, the input is parsed as a hex string. If false, it
         *      is parsed as a Base64 string. If this value is undefined, it is parsed as a UTF-8 string.
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
                        mime_type[ i ] = _discordCrypt.__getFileMimeType( tmp );

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
         * @private
         * @desc Converts a seed to the encryption keys used in the Up1 protocol.
         * @param {string|Buffer|Uint8Array} seed
         * @param {Object} sjcl The loaded Stanford Javascript Crypto Library.
         * @return {{seed: *, key: *, iv: *, ident: *}}
         */
        static __up1SeedToKey( seed, sjcl ) {
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

        /**
         * @public
         * @desc Encrypts the specified buffer to Up1's format specifications and returns this data to the callback.
         * @param {Buffer} data The input buffer to encrypt.
         * @param {string} mime_type The MIME type of this file.
         * @param {string} file_name The name of this file.
         * @param {Object} sjcl The loaded Stanford Javascript Crypto Library.
         * @param {EncryptedFileCallback} callback The callback function that will be called on error or completion.
         * @param {Buffer} [seed] Optional seed to use for the generation of keys.
         */
        static __up1EncryptBuffer( data, mime_type, file_name, sjcl, callback, seed ) {
            const crypto = require( 'crypto' );

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
                let params = _discordCrypt.__up1SeedToKey( seed || crypto.randomBytes( 64 ), sjcl );

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
         * @desc Decrypts the specified data as per Up1's spec.
         * @param {Buffer} data The encrypted buffer.
         * @param {string} seed A base64-URL encoded string.
         * @param {Object} sjcl The Stanford Javascript Library object.
         * @return {{header: Object, data: Blob}}
         * @private
         */
        static __up1DecryptBuffer( data, seed, sjcl ) {
            /* Constant as per the Up1 protocol. Every file contains these four bytes: "Up1\0". */
            const file_header = [ 85, 80, 49, 0 ];

            let has_header = true, idx = 0, header = '', view;

            /* Retrieve the AES key and IV. */
            let params = _discordCrypt.__up1SeedToKey( seed, sjcl );

            /* Convert the buffer to a Uint8Array. */
            let _file = new Uint8Array( data );

            /* Scan for the file header. */
            for ( let i = 0; i < file_header.length; i++ ) {
                if ( _file[ i ] != file_header[ i ] ) {
                    has_header = false;
                    break
                }
            }

            /* Remove the header if it exists. */
            if ( has_header )
                _file = _file.subarray( file_header.length );

            /* Decrypt the blob. */
            let decrypted = sjcl.mode.ccm.decrypt(
                new sjcl.cipher.aes( params.key ),
                sjcl.codec.bytes.toBits( _file ),
                params.iv
            );

            /* The header is a JSON encoded UTF-16 string at the top. */
            view = new DataView( ( new Uint8Array( sjcl.codec.bytes.fromBits( decrypted ) ) ).buffer );
            for ( ; ; idx++ ) {
                /* Get the UTF-16 byte at the position. */
                let num = view.getUint16( idx * 2, false );

                /* Break on null terminators. */
                if ( num === 0 )
                    break;

                /* Add to the JSON string. */
                header += String.fromCharCode( num );
            }

            /* Return the header object and the decrypted data. */
            header = JSON.parse( header );
            return {
                header: header,
                data: Buffer.from( sjcl.codec.bytes.fromBits( decrypted ) )
                    .slice( ( idx * 2 ) + 2, data.length ),
                blob: ( new Blob( [ decrypted ], { type: header.mime } ) )
                    .slice( ( idx * 2 ) + 2, data.length, header.mime )
            };
        }

        /**
         * @private
         * @desc Performs AES-256 CCM encryption of the given file and converts it to the expected Up1 format.
         * @param {string} file_path The path to the file to encrypt.
         * @param {Object} sjcl The loaded SJCL library providing AES-256 CCM.
         * @param {EncryptedFileCallback} callback The callback function for when the file has been encrypted.
         * @param {boolean} [randomize_file_name] Whether to randomize the name of the file in the metadata.
         *      Default: False.
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
                    _discordCrypt.__up1EncryptBuffer(
                        file_data,
                        _discordCrypt.__getFileMimeType( file_path ),
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
         * @desc Uploads raw data to an Up1 service and returns the file URL and deletion key.
         * @param {string} up1_host The host URL for the Up1 service.
         * @param {string} [up1_api_key] The optional API key used for the service.
         * @param {Object} sjcl The loaded SJCL library providing AES-256 CCM.
         * @param {UploadedFileCallback} callback The callback function called on success or failure.
         * @param {ClipboardInfo} [clipboard_data] Optional clipboard data.
         */
        static __up1UploadClipboard( up1_host, up1_api_key, sjcl, callback, clipboard_data = undefined ) {
            /* Get the current clipboard data. */
            let clipboard = clipboard_data === undefined ? _discordCrypt.__clipboardToBuffer() : clipboard_data;

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
         * @param {boolean} [randomize_file_name] Whether to randomize the name of the file in the metadata.
         *      Default: False.
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
                _discordCrypt.log( `Failed to parse the changelog: ${e}`, 'warn' );
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
                    _input = Buffer
                        .from( input, is_input_hex === undefined ? 'utf8' : is_input_hex ? 'hex' : 'base64' );
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
            _message = _discordCrypt.__toBuffer( message, is_hex );

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
         * @desc Converts a given key or iv into a buffer object. Performs a hash of the key it doesn't match the
         *      blockSize.
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
                    hash = _discordCrypt.__whirlpool64;
                    break;
                case 16:
                    hash = _discordCrypt.__sha512_128;
                    break;
                case 20:
                    hash = _discordCrypt.__sha160;
                    break;
                case 24:
                    hash = _discordCrypt.__whirlpool192;
                    break;
                case 32:
                    hash = _discordCrypt.__sha256;
                    break;
                case 64:
                    hash = use_whirlpool !== undefined ? _discordCrypt.__sha512 : _discordCrypt.__whirlpool;
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
                return _discordCrypt.__toBuffer( message, is_message_hex );
            }
            catch ( e ) {
                throw 'exception - Invalid message type.';
            }
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
        static __cipherStringToIndex( primary_cipher, secondary_cipher = undefined ) {
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
        static __cipherIndexToString( index, get_secondary = undefined ) {

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
        static __entropicBitLength( key ) {
            let h = Object.create( null ), k;
            let sum = 0, len = key.length;

            key.split( '' ).forEach( c => {
                h[ c ] ? h[ c ]++ : h[ c ] = 1;
            } );

            for ( k in h ) {
                let p = h[ k ] / len;
                sum -= p * Math.log2( p );
            }

            return parseInt( sum * len );
        }

        /**
         * @public
         * @desc Returns 256-characters of Braille.
         * @return {string}
         */
        static __getBraille() {
            return Array.from(
                "⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿⡀⡁⡂⡃⡄⡅⡆⡇⡈⡉⡊⡋⡌⡍⡎⡏⡐⡑⡒⡓⡔⡕⡖" +
                "⡗⡘⡙⡚⡛⡜⡝⡞⡟⡠⡡⡢⡣⡤⡥⡦⡧⡨⡩⡪⡫⡬⡭⡮⡯⡰⡱⡲⡳⡴⡵⡶⡷⡸⡹⡺⡻⡼⡽⡾⡿⢀⢁⢂⢃⢄⢅⢆⢇⢈⢉⢊⢋⢌⢍⢎⢏⢐⢑⢒⢓⢔⢕⢖⢗⢘⢙⢚⢛⢜⢝⢞⢟⢠⢡⢢⢣⢤⢥⢦⢧⢨⢩⢪⢫⢬⢭" +
                "⢮⢯⢰⢱⢲⢳⢴⢵⢶⢷⢸⢹⢺⢻⢼⢽⢾⢿⣀⣁⣂⣃⣄⣅⣆⣇⣈⣉⣊⣋⣌⣍⣎⣏⣐⣑⣒⣓⣔⣕⣖⣗⣘⣙⣚⣛⣜⣝⣞⣟⣠⣡⣢⣣⣤⣥⣦⣧⣨⣩⣪⣫⣬⣭⣮⣯⣰⣱⣲⣳⣴⣵⣶⣷⣸⣹⣺⣻⣼⣽⣾⣿"
            );
        }

        /**
         * @public
         * @desc Determines if a string has all valid Braille characters according to the result from __getBraille()
         * @param {string} message The message to validate.
         * @returns {boolean} Returns true if the message contains only the required character set.
         */
        static __isValidBraille( message ) {
            let c = _discordCrypt.__getBraille();

            for ( let i = 0; i < message.length; i++ )
                if ( c.indexOf( message[ i ] ) === -1 )
                    return false;

            return true;
        }

        /**
         * @public
         * @desc Returns an array of valid Diffie-Hellman exchange key bit-sizes.
         * @returns {number[]} Returns the bit lengths of all supported DH keys.
         */
        static __getDHBitSizes() {
            return [ 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192 ];
        }

        /**
         * @public
         * @desc Returns an array of Elliptic-Curve Diffie-Hellman key bit-sizes.
         * @returns {number[]} Returns the bit lengths of all supported ECDH keys.
         */
        static __getECDHBitSizes() {
            return [ 224, 256, 384, 409, 521, 571 ];
        }

        /**
         * @public
         * @desc Determines if a key exchange algorithm's index is valid.
         * @param {int} index The index to determine if valid.
         * @returns {boolean} Returns true if the desired index meets one of the ECDH or DH key sizes.
         */
        static __isValidExchangeAlgorithm( index ) {
            return index >= 0 &&
                index <= ( _discordCrypt.__getDHBitSizes().length + _discordCrypt.__getECDHBitSizes().length - 1 );
        }

        /**
         * @public
         * @desc Converts an algorithm index to a string.
         * @param {int} index The input index of the exchange algorithm.
         * @returns {string} Returns a string containing the algorithm or "Invalid Algorithm".
         */
        static __indexToExchangeAlgorithmString( index ) {
            let dh_bl = _discordCrypt.__getDHBitSizes(), ecdh_bl = _discordCrypt.__getECDHBitSizes();
            let base = [ 'DH-', 'ECDH-' ];

            if ( !_discordCrypt.__isValidExchangeAlgorithm( index ) )
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
        static __indexToAlgorithmBitLength( index ) {
            let dh_bl = _discordCrypt.__getDHBitSizes(), ecdh_bl = _discordCrypt.__getECDHBitSizes();

            if ( !_discordCrypt.__isValidExchangeAlgorithm( index ) )
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
        static __computeExchangeSharedSecret( private_key, public_key, is_base_64, to_base_64 ) {
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
         *      This must be one of the supported lengths retrieved from __getDHBitSizes().
         * @param {Buffer} private_key The optional private key used to initialize the object.
         * @returns {Object|null} Returns a DiffieHellman object on success or null on failure.
         */
        static __generateDH( size, private_key = undefined ) {
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
         *      This must be one of the supported lengths retrieved from __getECDHBitSizes().
         * @param {Buffer} private_key The optional private key used to initialize the object.
         * @returns {Object|null} Returns a ECDH object on success or null on failure.
         */
        static __generateECDH( size, private_key = undefined ) {
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
         * @desc Substitutes an input Buffer() object to the Braille equivalent from __getBraille().
         * @param {string} message The input message to perform substitution on.
         * @param {boolean} convert Whether the message is to be converted from hex to Braille or from Braille to hex.
         * @returns {string} Returns the substituted string encoded message.
         * @throws An exception indicating the message contains characters not in the character set.
         */
        static __substituteMessage( message, convert ) {
            /* Target character set. */
            let subset = _discordCrypt.__getBraille();

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
         * @returns {string} Returns a substituted UTF-16 string of a braille encoded 32-bit word containing these
         *      options.
         */
        static __metaDataEncode( cipher_index, cipher_mode_index, padding_scheme_index, pad_byte ) {

            /* Parse the first 8 bits. */
            if ( typeof cipher_index === 'string' )
                cipher_index = _discordCrypt.__cipherStringToIndex( cipher_index );

            /* Parse the next 8 bits. */
            if ( typeof cipher_mode_index === 'string' )
                cipher_mode_index = [ 'cbc', 'cfb', 'ofb' ].indexOf( cipher_mode_index.toLowerCase() );

            /* Parse the next 8 bits. */
            if ( typeof padding_scheme_index === 'string' )
                padding_scheme_index = [ 'pkc7', 'ans2', 'iso1', 'iso9' ].indexOf( padding_scheme_index.toLowerCase() );

            /* Buffered word. */
            let buf = Buffer.from( [ cipher_index, cipher_mode_index, padding_scheme_index, parseInt( pad_byte ) ] );

            /* Convert it and return. */
            return _discordCrypt.__substituteMessage( buf, true );
        }

        /**
         * @public
         * @desc Decodes an input string and returns a byte array containing index number of options.
         * @param {string} message The substituted UTF-16 encoded metadata containing the metadata options.
         * @returns {int[]} Returns 4 integer indexes of each metadata value.
         */
        static __metaDataDecode( message ) {
            /* Decode the result and convert the hex to a Buffer. */
            return Buffer.from( _discordCrypt.__substituteMessage( message ), 'hex' );
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
                !_discordCrypt.__isValidCipher( cipher_name ) || [ 'cbc', 'cfb', 'ofb' ]
                    .indexOf( block_mode.toLowerCase() ) === -1
            )
                return null;

            /* Pad the message to the nearest block boundary. */
            _message = _discordCrypt.__padMessage( message, padding_scheme, key_size_bits, is_message_hex );

            /* Get the key as a buffer. */
            _key = _discordCrypt.__validateKeyIV( key, key_size_bits );

            /* Check if using a predefined salt. */
            if ( one_time_salt !== undefined ) {
                /* Convert the salt to a Buffer. */
                _salt = _discordCrypt.__toBuffer( one_time_salt );

                /* Don't bother continuing if conversions have failed. */
                if ( !_salt || _salt.length === 0 )
                    return null;

                /* Only 64 bits is used for a salt. If it's not that length, hash it and use the result. */
                if ( _salt.length !== 8 )
                    _salt = Buffer.from( _discordCrypt.__whirlpool64( _salt, true ), 'hex' );
            }
            else {
                /* Generate a random salt to derive the key and IV. */
                _salt = crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            _derived = _discordCrypt.__pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
         * @param {string} padding_scheme The padding scheme used to unpad the message from the block length of the
         *      cipher.
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
            if ( !_discordCrypt.__isValidCipher( cipher_name ) || [ 'cbc', 'ofb', 'cfb' ]
                .indexOf( block_mode.toLowerCase() ) === -1 )
                return null;

            /* Get the message as a buffer. */
            _message = _discordCrypt.__validateMessage( message, is_message_hex );

            /* Get the key as a buffer. */
            _key = _discordCrypt.__validateKeyIV( key, key_size_bits );

            /* Retrieve the 64-bit salt. */
            _salt = _message.slice( 0, 8 );

            /* Derive the key length and IV length. */
            _derived = _discordCrypt.__pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
            _pt = _discordCrypt.__padMessage( _pt, padding_scheme, key_size_bits, true, true );

            /* Return the buffer. */
            return _pt.toString( output_format );
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
        static __symmetricEncrypt( message, primary_key, secondary_key, cipher_index, block_mode, padding_mode ) {
            const customizationParameter = new Uint8Array( Buffer.from( 'discordCrypt MAC' ) );

            /* Performs one of the 5 standard encryption algorithms on the plain text. */
            function handleEncodeSegment( message, key, cipher, mode, pad ) {
                switch ( cipher ) {
                case 0:
                    return _discordCrypt.__blowfish512_encrypt( message, key, mode, pad );
                case 1:
                    return _discordCrypt.__aes256_encrypt( message, key, mode, pad );
                case 2:
                    return _discordCrypt.__camellia256_encrypt( message, key, mode, pad );
                case 3:
                    return _discordCrypt.__idea128_encrypt( message, key, mode, pad );
                case 4:
                    return _discordCrypt.__tripledes192_encrypt( message, key, mode, pad );
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
                msg = _discordCrypt.__blowfish512_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 5 && cipher_index <= 9 )
                msg = _discordCrypt.__aes256_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index - 5, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 10 && cipher_index <= 14 )
                msg = _discordCrypt.__camellia256_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index - 10, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 15 && cipher_index <= 19 )
                msg = _discordCrypt.__idea128_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index - 15, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 20 && cipher_index <= 24 )
                msg = _discordCrypt.__tripledes192_encrypt(
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
            let tag = sha3.kmac256(
                new Uint8Array( Buffer.concat( [ primary_key, secondary_key ] ) ),
                new Uint8Array( Buffer.from( msg, 'hex' ) ),
                256,
                customizationParameter
            );

            /* Prepend the authentication tag hex string & convert it to Base64. */
            msg = Buffer.from( tag + msg, 'hex' );

            /* Return the message. */
            return _discordCrypt.__substituteMessage( msg, true );
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
        static __symmetricDecrypt( message, primary_key, secondary_key, cipher_index, block_mode, padding_mode ) {
            const customizationParameter = new Uint8Array( Buffer.from( 'discordCrypt MAC' ) );
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
                    return _discordCrypt.__blowfish512_decrypt(
                        message,
                        key,
                        mode,
                        pad,
                        output_format,
                        is_message_hex
                    );
                case 1:
                    return _discordCrypt.__aes256_decrypt( message, key, mode, pad, output_format, is_message_hex );
                case 2:
                    return _discordCrypt.__camellia256_decrypt(
                        message,
                        key,
                        mode,
                        pad,
                        output_format,
                        is_message_hex
                    );
                case 3:
                    return _discordCrypt.__idea128_decrypt( message, key, mode, pad, output_format, is_message_hex );
                case 4:
                    return _discordCrypt.__tripledes192_decrypt( message,
                        key,
                        mode,
                        pad,
                        output_format,
                        is_message_hex
                    );
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
                message = Buffer.from( _discordCrypt.__substituteMessage( message ), 'hex' );

                /* Pull off the first 32 bytes as a buffer. */
                let tag = Buffer.from( message.subarray( 0, 32 ) );

                /* Strip off the authentication tag. */
                message = Buffer.from( message.subarray( 32 ) );

                /* Compute the HMAC-SHA3-256 of the cipher text as hex. */
                let computed_tag = Buffer.from(
                    sha3.kmac256(
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
                        _discordCrypt.__blowfish512_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 5 && cipher_index <= 9 )
                    return handleDecodeSegment(
                        _discordCrypt.__aes256_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index - 5,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 10 && cipher_index <= 14 )
                    return handleDecodeSegment(
                        _discordCrypt.__camellia256_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index - 10,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 15 && cipher_index <= 19 )
                    return handleDecodeSegment(
                        _discordCrypt.__idea128_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index - 15,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 20 && cipher_index <= 24 )
                    return handleDecodeSegment(
                        _discordCrypt.__tripledes192_decrypt( message, secondary_key, mode, pad, 'base64' ),
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
        static __scrypt( input, salt, output_length, N = 16384, r = 8, p = 1, cb = null ) {
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
                    _discordCrypt.log( 'Invalid input parameter type specified!', 'error' );
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
                    _discordCrypt.log( 'Invalid salt parameter type specified!', 'error' );
                    return false;
                }
            }

            /* Validate derived key length. */
            if ( typeof output_length !== 'number' ) {
                _discordCrypt.log( 'Invalid output_length parameter specified. Must be a numeric value.', 'error' );
                return false;
            }
            else if ( output_length <= 0 || output_length >= 65536 ) {
                _discordCrypt.log( 'Invalid output_length parameter specified. Must be a numeric value.', 'error' );
                return false;
            }

            /* Validate N is a power of 2. */
            if ( !N || N & ( N - 1 ) !== 0 ) {
                _discordCrypt.log( 'Parameter N must be a power of 2.', 'error' );
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
            _discordCrypt.log( 'No callback specified.', 'error' );
            return false;
        }

        /**
         * @public
         * @desc Returns the first 64 bits of a Whirlpool digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __whirlpool64( message, to_hex ) {
            return Buffer.from( _discordCrypt.__whirlpool( message, true ), 'hex' )
                .slice( 0, 8 ).toString( to_hex ? 'hex' : 'base64' );
        }

        /**
         * @public
         * @desc Returns the first 128 bits of an SHA-512 digest of a message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __sha512_128( message, to_hex ) {
            return Buffer.from( _discordCrypt.__sha512( message, true ), 'hex' )
                .slice( 0, 16 ).toString( to_hex ? 'hex' : 'base64' );
        }

        /**
         * @public
         * @desc Returns the first 192 bits of a Whirlpool digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __whirlpool192( message, to_hex ) {
            return Buffer.from( _discordCrypt.__sha512( message, true ), 'hex' )
                .slice( 0, 24 ).toString( to_hex ? 'hex' : 'base64' );
        }

        /**
         * @public
         * @desc Returns an SHA-160 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __sha160( message, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha1', to_hex );
        }

        /**
         * @public
         * @desc Returns an SHA-256 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __sha256( message, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha256', to_hex );
        }

        /**
         * @public
         * @desc Returns an SHA-512 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __sha512( message, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha512', to_hex );
        }

        /**
         * @public
         * @desc Returns a Whirlpool-512 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __whirlpool( message, to_hex ) {
            return _discordCrypt.__createHash( message, 'whirlpool', to_hex );
        }

        /**
         * @public
         * @desc Returns a HMAC-SHA-256 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {Buffer|Array|string} secret The secret input used with the message.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __hmac_sha256( message, secret, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha256', to_hex, true, secret );
        }

        /**
         * @public
         * @desc Returns an HMAC-SHA-512 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {Buffer|Array|string} secret The secret input used with the message.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __hmac_sha512( message, secret, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha512', to_hex, true, secret );
        }

        /**
         * @public
         * @desc Returns an HMAC-Whirlpool-512 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {Buffer|Array|string} secret The secret input used with the message.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static __hmac_whirlpool( message, secret, to_hex ) {
            return _discordCrypt.__createHash( message, 'whirlpool', to_hex, true, secret );
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
        static __pbkdf2_sha160(
            message,
            salt,
            to_hex,
            message_is_hex = undefined,
            salt_is_hex = undefined,
            key_length = 32,
            iterations = 5000,
            callback = undefined
        ) {
            return _discordCrypt.__pbkdf2(
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
        static __pbkdf2_sha256(
            message,
            salt,
            to_hex,
            message_is_hex = undefined,
            salt_is_hex = undefined,
            key_length = 32,
            iterations = 5000,
            callback = undefined
        ) {
            return _discordCrypt.__pbkdf2(
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
        static __pbkdf2_sha512(
            message,
            salt,
            to_hex,
            message_is_hex = undefined,
            salt_is_hex = undefined,
            key_length = 32,
            iterations = 5000,
            callback = undefined
        ) {
            return _discordCrypt.__pbkdf2(
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
        static __pbkdf2_whirlpool(
            message,
            salt,
            to_hex,
            message_is_hex = undefined,
            salt_is_hex = undefined,
            key_length = 32,
            iterations = 5000,
            callback = undefined
        ) {
            return _discordCrypt.__pbkdf2(
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
        static __blowfish512_encrypt(
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
            return _discordCrypt.__encrypt(
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
        static __blowfish512_decrypt(
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
            return _discordCrypt.__decrypt(
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
        static __aes256_encrypt(
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
            return _discordCrypt.__encrypt(
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
        static __aes256_decrypt(
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
            return _discordCrypt.__decrypt(
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
        static __aes256_encrypt_gcm(
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
            _message = _discordCrypt.__padMessage( message, padding_mode, key_size_bits, is_message_hex );

            /* Get the key as a buffer. */
            _key = _discordCrypt.__validateKeyIV( key, key_size_bits );

            /* Check if using a predefined salt. */
            if ( one_time_salt !== undefined ) {
                /* Convert the salt to a Buffer. */
                _salt = _discordCrypt.__toBuffer( one_time_salt );

                /* Don't bother continuing if conversions have failed. */
                if ( !_salt || _salt.length === 0 )
                    return null;

                /* Only 64 bits is used for a salt. If it's not that length, hash it and use the result. */
                if ( _salt.length !== 8 )
                    _salt = Buffer.from( _discordCrypt.__whirlpool64( _salt, true ), 'hex' );
            }
            else {
                /* Generate a random salt to derive the key and IV. */
                _salt = crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            _derived = _discordCrypt.__pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
                ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), kdf_iteration_rounds );

            /* Slice off the IV. */
            _iv = _derived.slice( 0, block_cipher_size / 8 );

            /* Slice off the key. */
            _key = _derived.slice( block_cipher_size / 8, ( block_cipher_size / 8 ) + ( key_size_bits / 8 ) );

            /* Create the cipher with derived IV and key. */
            _encrypt = crypto.createCipheriv( cipher_name, _key, _iv );

            /* Add the additional data if necessary. */
            if ( additional_data !== undefined )
                _encrypt.setAAD( _discordCrypt.__toBuffer( additional_data ) );

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
        static __aes256_decrypt_gcm(
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
            _message = _discordCrypt.__validateMessage( message, is_message_hex );

            /* Get the key as a buffer. */
            _key = _discordCrypt.__validateKeyIV( key, key_size_bits );

            /* Retrieve the auth tag. */
            _authTag = _message.slice( 0, block_cipher_size / 8 );

            /* Splice the message. */
            _message = _message.slice( block_cipher_size / 8 );

            /* Retrieve the 64-bit salt. */
            _salt = _message.slice( 0, 8 );

            /* Splice the message. */
            _message = _message.slice( 8 );

            /* Derive the key length and IV length. */
            _derived = _discordCrypt.__pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
                _decrypt.setAAD( _discordCrypt.__toBuffer( additional_data ) );

            /* Disable automatic PKCS #7 padding. We do this in-house. */
            _decrypt.setAutoPadding( false );

            /* Decrypt the cipher text. */
            let _pt = _decrypt.update( _message, undefined, 'hex' );
            _pt += _decrypt.final( 'hex' );

            /* Unpad the message. */
            _pt = _discordCrypt.__padMessage( _pt, padding_mode, key_size_bits, true, true );

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
        static __camellia256_encrypt(
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
            return _discordCrypt.__encrypt(
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
        static __camellia256_decrypt(
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
            return _discordCrypt.__decrypt(
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
        static __tripledes192_encrypt(
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
            return _discordCrypt.__encrypt(
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
        static __tripledes192_decrypt(
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
            return _discordCrypt.__decrypt(
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
        static __idea128_encrypt(
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
            return _discordCrypt.__encrypt(
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
        static __idea128_decrypt(
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
            return _discordCrypt.__decrypt(
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

        /* ========================================================= */
    }

    /* Freeze the prototype. */
    _freeze( _discordCrypt.prototype );

    /* Freeze the class definition. */
    _freeze( _discordCrypt );

    return _discordCrypt;
} )();

/* Also freeze the method. */
Object.freeze( discordCrypt );

/* Required for code coverage reports. */
module.exports = { discordCrypt };
