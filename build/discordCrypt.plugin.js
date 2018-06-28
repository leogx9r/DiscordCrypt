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
     */

    /**
     * @typedef {Object} UpdateCallback
     * @desc The function to execute after an update has been retrieved.
     * @property {string} file_data The update file's data.
     * @property {string} short_hash A 64-bit SHA-256 checksum of the new update.
     * @property {string} new_version The new version of the update.
     * @property {string} full_changelog The full changelog.
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
            'currify.js': {"requiresElectron":false,"requiresBrowser":true,"code":"eNqdVFFv2yAQ/iuONaWgEit5jUujae2etvZlfbKs1rWhYaLgYWgWOfz3gcFOKuWh3Ys5HXcfd9995xk1otZMCiBgzyhI5fNvUusUY71viaQJ+dtKpbv5PDWiIZQJ0qSz8fJVNoYTGI4shmIBYE54RxKPN+IfEQPKfB7OrHptYDBBUSIRUntOdKJyoPC5Z3dMNHK3Ccf6XMQLl88V34TjbERHON34z1pvWQez2ijF6N4Xby2YWIH9W6USgRQiuSLaKJGMd4kAzos07CePBBSZgccZKWgZLDVYHqbGZ+hQ5I9hyvERjdznmPm8hvG92oHOltD72ehj0edRORZkl9wqJRV4+lYJIXXimm3idJKLLz21F08w11sldwnPatkQnP68v3n4cft4d//r8fv9w91Nirj1cC32peM+TnPdW5v7FoplmdUV56AdB41OteNTCR4CV2UhypEtCcjhIKBFLTomDnw65mwM8i+Ol0MR7ENMUdexF4rAy1xc6YwT8aK3ubi8hBJoVwScqrCgjxNeF8eyfRmwT43TaqcVc7ofGNX4dMawDyDFabsRV2VV2/I9eJOsSZaoUi/mlQjduX5PXiGfjfei+mwGkv+Tg9gHskqbn0g8/iim+UwrJWBQWJBiSkXSbaXhTfJMpqWZpW7o05/iPc1+nEFG09txpIjhr0pVe0CuVxuyWK2XEFG8yumVE4GbNivoYlUe05yc/LpIh4pYxLjGKlrwfMMsrJM5VkXARI54H1sotwxS1JUGDA2lZa2SWnomso6zmoRdOZIIHfn1VMJirGqxQnwUqQYGFnV5OBhrUe9Ydx9UpFG3aQnBZEML838pAQw+"},
            'curve25519.js': {"requiresElectron":true,"requiresBrowser":false,"code":"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"},
            'sha3.js': {"requiresElectron":true,"requiresBrowser":false,"code":"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"},
            'sjcl.js': {"requiresElectron":true,"requiresBrowser":false,"code":"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"},
            'smalltalk.js': {"requiresElectron":false,"requiresBrowser":true,"code":"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"},
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
        return '1.2.6';
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
        let data = bdPluginStorage.get( this.getName(), 'config' );

        /* Check if the config file exists. */
        if ( !data || data === null || data === '' ) {
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
                discordCrypt.aes256_decrypt_gcm( data.data, this.masterPassword, 'PKC7', 'utf8', false )
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
                    JSON.stringify( this.configFile ),
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
                discordCrypt.checkForUpdate( ( file_data, short_hash, new_version, full_changelog ) => {
                    const replacePath = require( 'path' )
                        .join( discordCrypt.getPluginsPath(), discordCrypt.getPluginName() );
                    const fs = require( 'fs' );

                    /* Alert the user of the update and changelog. */
                    $( '#dc-overlay' ).css( 'display', 'block' );
                    $( '#dc-update-overlay' ).css( 'display', 'block' );

                    /* Update the version info. */
                    $( '#dc-new-version' )
                        .text( `New Version: ${new_version === '' ? 'N/A' : new_version} ( #${short_hash} )` );
                    $( '#dc-old-version' ).text( `Old Version: ${self.getVersion()}` );

                    /* Update the changelog. */
                    let dc_changelog = $( '#dc-changelog' );
                    dc_changelog.val(
                        typeof full_changelog === "string" && full_changelog.length > 0 ?
                            full_changelog :
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
        }, 1000 );
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
     * @private
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
     * @private
     * @desc Checks the update server for an encrypted update.
     * @param {UpdateCallback} on_update_callback
     * @returns {boolean}
     * @example
     * checkForUpdate( ( file_data, short_hash, new_version, full_changelog ) =>
     *      console.log( `New Update Available: #${short_hash} - v${new_version}` );
     *      console.log( `Changelog:\n${full_changelog}` );
     * } );
     */
    static checkForUpdate( on_update_callback ) {
        /* Update URL and request method. */
        const update_url = `https://gitlab.com/leogx9r/DiscordCrypt/raw/master/build/${discordCrypt.getPluginName()}`;
        const changelog_url = 'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/src/CHANGELOG';

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

                /* Format properly. */
                data = data.replace( '\r', '' );

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
                let currentHash = discordCrypt.sha256( localFile );
                let hash = discordCrypt.sha256( data );
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

                /* Now get the changelog. */
                try {
                    /* Fetch the changelog from the URL. */
                    discordCrypt.__getRequest( changelog_url, ( statusCode, errorString, changelog ) => {
                        /* Perform the callback. */
                        on_update_callback( data, shortHash, version_number, statusCode == 200 ? changelog : '' );
                    } );
                }
                catch ( e ) {
                    discordCrypt.log( 'Error fetching the changelog.', 'warn' );

                    /* Perform the callback without a changelog. */
                    on_update_callback( data, shortHash, version_number, '' );

                    return false;
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
     * @returns {{find, findByUniqueProperties, findByDisplayName, findByDispatchToken, findByDispatchNames}}
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
         * @desc Look through all modules of internal Discord's Webpack and return first object that has
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

        return { find, findByUniqueProperties, findByDisplayName, findByDispatchToken, findByDispatchNames };
    }

    /**
     * @private
     * @experimental
     * @desc Dumps all function callback handlers with their names, IDs and function prototypes. [ Debug Function ]
     * @param {boolean} [dump_actions] Whether to dump action handlers.
     * @returns {Array} Returns an array of all IDs and identifier callbacks.
     */
    static dumpWebpackModuleCallbacks( dump_actions = true ) {
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
                /* Skip dependencies. */
                if( prop == '_dependencies' )
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
     * @public
     * @desc Decompresses an encoded ZLIB package.
     * @param {string} data The input data to decompress.
     * @param {string} [format] The format of the input data.
     *      Can be either hex, base64, latin1, utf8 or undefined.
     *      Defaults to Base64.
     * @return {string} The original data.
     */
    static __zlibDecompress( data, format = 'base64' ) {
        return require( 'zlib' ).inflateSync(
            Buffer.from( data, format ),
            { windowBits: 15 }
        ).toString( 'utf8' );
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
