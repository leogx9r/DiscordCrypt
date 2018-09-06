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
 * @typedef {Object} ModulePredicate
 * @desc Predicate for searching module.
 * @property {*} module Module to test.
 * @return {boolean} Returns `true` if `module` matches predicate.
 */

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
 * @property {WebpackFinder} find Recursively iterates all webpack modules to the callback function.
 * @property {WebpackPrototypeFinder} findByUniquePrototypes Iterates all modules looking for the defined prototypes.
 * @property {WebpackPropertyFinder} findByUniqueProperties Iterates all modules look for the defined properties.
 * @property {WebpackDisplayNameFinder} findByDisplayName Iterates all modules looking for the specified display name.
 * @property {WebpackModuleIdFinder} findByDispatchToken Iterates all modules looking for the dispatch token by its ID.
 * @property {WebpackDispatchFinder} findByDispatchNames Iterates all modules looking for the specified dispatch names.
 */

/**
 * @typedef {Object} CachedModules
 * @desc Cached Webpack modules for internal access.
 * @property {Object} NonceGenerator Internal nonce generator used for generating unique IDs from the current time.
 * @property {Object} ChannelStore Internal channel resolver for retrieving a list of all channels available.
 * @property {Object} GlobalTypes Internal message action types and constants for events.
 * @property {Object} GuildStore Internal Guild resolver for retrieving a list of all guilds currently in.
 * @property {Object} MessageCreator Internal message parser that's used to translate tags to Discord symbols.
 * @property {Object} MessageController Internal message controller used to receive, send and delete messages.
 * @property {Object} EventDispatcher Internal message dispatcher for pending queued messages.
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
 * @typedef {Object} PublicKeyInfo
 * @desc Contains information given an input public key.
 * @property {number} index The index of the exchange algorithm.
 * @property {string} fingerprint The SHA-256 sum of the public key.
 * @property {string} algorithm The public key's type ( DH | ECDH ) extracted from the metadata.
 * @property {int} bit_length The length, in bits, of the public key's security.
 * @property {Buffer} salt The unique salt for this key.
 * @property {Buffer} key The raw key.
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
 * @typedef {Object} ChannelStore
 * @desc Storage information settings relating to the channel.
 * @property {string} [primaryKey] Primary encryption key.
 * @property {string} [secondaryKey] Secondary encryption key.
 * @property {string[]} ignoreIds Message IDs to exclude from parsing.
 * @property {boolean} autoEncrypt Whether to automatically encrypt messages.
 */

/**
 * @typedef {Object} ChannelInfo
 * @desc Contains settings regarding all channels.
 * @property {string} channelId Channel's specific ID number.
 * @property {ChannelStore} store Individual storage for this channel.
 */

/**
 * @typedef {Object} Config
 * @desc Contains the configuration data used for the plugin.
 * @property {string} version The version of the configuration.
 * @property {string} defaultPassword The default key to encrypt or decrypt message with, if not specifically defined.
 * @property {string} decryptedPrefix The string that should be prepended to messages that have been decrypted.
 * @property {string} encodeMessageTrigger The suffix trigger which, once appended to the message,
 *      forces encryption even if a key is not specifically defined for this channel.
 * @property {number} encryptMode The index of the ciphers to use for message encryption.
 * @property {string} encryptBlockMode The block operation mode of the ciphers used to encrypt message.
 * @property {number} exchangeBitSize The size in bits of the exchange algorithm to use.
 * @property {string} paddingMode Padding scheme to used to align all messages to the cipher's block length.
 * @property {string} up1Host The full URI host of the Up1 service to use for encrypted file uploads.
 * @property {string} up1ApiKey If specified, contains the API key used for authentication with the up1Host.
 * @property {Array<TimedMessage>} timedMessages Contains all logged timed messages pending deletion.
 * @property {number} timedMessageExpires How long after a message is sent should it be deleted in seconds.
 * @property {boolean} automaticUpdates Whether to automatically check for updates.
 * @property {Array<UpdateInfo>} blacklistedUpdates Updates to ignore due to being blacklisted.
 * @property {ChannelInfo} channels Specific data per channel.
 */

/**
 * @typedef {Object} UpdateCallback
 * @desc The function to execute after an update has been retrieved or if an error occurs.
 * @property {UpdateInfo} [info] The update's information if valid.
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
 * @typedef {Object} UserMention
 * @desc Contains a user-specific mention.
 * @property {string} avatar The user's avatar hash.
 * @property {string} discriminator The user's 4-digit discriminator.
 * @property {string} id The user's unique identification number.
 * @property {string} username The user's account name. ( Not display name. )
 */

/**
 * @typedef {Object} MessageMentions
 * @desc Contains information on what things were mentioned in a message.
 * @property {boolean} mention_everyone Whether "@everyone" was used in the message.
 * @property {Array<UserMention>} mentions Contains all user IDs mentioned in a message.
 * @property {Array<string>} mention_roles Roles that were mentioned.
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
 * @typedef {Object} MessageAuthor
 * @desc The author of a message.
 * @property {string} avatar The hash name of the user's avatar.
 * @property {string} discriminator The 4-digit discriminator value for this user.
 * @property {string} id The snowflake ID for the user.
 * @property {string} username The name of the user.
 */

/**
 * @typedef {Object} MemberInfo
 * @desc The author of a message.
 * @property {boolean} deaf Whether this user has been deafened.
 * @property {string} joined_at The time the user joined
 * @property {boolean} mute Whether the user is muted.
 * @property {string} [nick] The nickname of the user, if any.
 */

/**
 * @typedef {Object} Message
 * @desc An incoming or outgoing Discord message.
 * @property {Array<Object>} attachments Message attachments, if any.
 * @property {MessageAuthor} author The creator of the message.
 * @property {string} channel_id The channel this message belongs to.
 * @property {string} content The raw message content.
 * @property {string} [edited_timestamp] If specified, when this message was edited.
 * @property {string} [guild_id] If this message belongs to a Guild, this is the ID for it.
 * @property {string} id The message's unique ID.
 * @property {MemberInfo} member The statistics for the author.
 * @property {boolean} mention_everyone Whether this message attempts to mention everyone.
 * @property {string[]} mentions User IDs or roles mentioned in this message.
 * @property {string} nonce The unique timestamp/snowflake for this message.
 * @property {boolean} pinned Whether this message was pinned.
 * @property {string} timestamp When this message was sent.
 * @property {boolean} tts If this message should use TTS.
 * @property {number} type The type of message this is.
 */

/**
 * @callback EventHookCallback
 * @desc This callback is executed when an event occurs.
 * @desc {Object} event The event data that has occurred.
 */

/**
 * @typedef {Object} EventHook
 * @desc Defines an event that is handled via the dispatch event.
 * @property {string} type The type of event that's handled.
 * @property {EventHookCallback} callback The callback event to be executed.
 */

/**
 * @typedef {Object} PublicKeyInfo
 * @desc Information on a public key used for a key exchange.
 * @property {Buffer} salt The user-generated salt used with this public key.
 * @property {Buffer} key The raw public key buffer.
 * @property {string} algorithm The exchange algorithm being used.
 * @property {number} bit_length The length, in bits, of the public key.
 * @property {string} fingerprint The SHA-256 sum of the public key.
 */

/**
 * @typedef {Object} SessionKeyState
 * @desc Indicates an active key exchange session.
 * @property {PublicKeyInfo} [remoteKey] The remote party's public key.
 * @property {PublicKeyInfo} [localKey] The local public key information for the session.
 * @property {Object} [privateKey] The local private key corresponding to the local public key.
 * @property {string} initiateTime The time this exchange was initiated.
 */

/**
 * @typedef {Object} GlobalSessionState
 * @desc Contains all session states being actively established.
 * @property {string} channelId The channel this session establishment is taking place in.
 * @property {SessionKeyState} state The local state for the session.
 */

/**
 * @interface
 * @name PatchData
 * @desc Contains local patch data and state of the function.
 * @property {object} thisObject Original `this` value in current call of patched method.
 * @property {Arguments} methodArguments Original `arguments` object in current call of patched method.
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
 *      available only in `after` callback or in `instead` callback after calling `callOriginalMethod` function.
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
     * @desc Internal class instance.
     * @type {_discordCrypt}
     */
    let _self = null;

    /**
     * @private
     * @desc Master database password. This is a Buffer() containing a 256-bit key.
     * @type {Buffer|null}
     */
    let _masterPassword = null;

    /**
     * @private
     * @desc Used to store all event dispatcher hooks.
     * @type {Array<EventHook>}
     */
    let _eventHooks = [];

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
     * @desc Stores the update data for applying later on.
     * @type {UpdateInfo}
     */
    let _updateData = {};

    /**
     * @private
     * @desc Array containing function callbacks to execute when stopping the plugin.
     * @type {Array<function>}
     */
    let _stopCallbacks = [];

    /**
     * @private
     * @desc Contains all active sessions that are being established.
     * @type {GlobalSessionState}
     */
    let _globalSessionState = {};

    /**
     * @private
     * @desc The original methods of the Object descriptor as well as a prototype to freeze all object's props.
     * @type {{freeze: function, isFrozen: function, getOwnPropertyNames: function, _freeze: function}}
     */
    const _Object = {
        freeze: Object.freeze,
        isFrozen: Object.isFrozen,
        getOwnPropertyNames: Object.getOwnPropertyNames,
        _freeze: ( object ) => {
            /* Skip non-objects. */
            if( !object || typeof object !== 'object' )
                return;

            /* Recursively freeze all properties. */
            for( let prop in _Object.getOwnPropertyNames( object ) )
                _Object._freeze( object[ prop ] );

            /* Freeze the object. */
            _Object.freeze( object );
        }
    };

    /**
     * @private
     * @desc Defines how many bytes can be sent in a single message that Discord will allow prior to encryption.
     * @type {number}
     */
    const MAX_ENCODED_DATA = 1820;

    /**
     * @private
     * @desc Defines what an encrypted message starts with. Must be 4x UTF-16 bytes.
     * @type {string}
     */
    const ENCODED_MESSAGE_HEADER = "⢷⢸⢹⢺";

    /**
     * @private
     * @desc Defines what a public key message starts with. Must be 4x UTF-16 bytes.
     * @type {string}
     */
    const ENCODED_KEY_HEADER = "⢻⢼⢽⢾";

    /**
     * @private
     * @desc How long after a key-exchange message has been sent should it be ignored in milliseconds.
     * @type {number}
     */
    const KEY_IGNORE_TIMEOUT = 6 * 60 * 60 * 1000;

    /**
     * @private
     * @desc How long after a key exchange message is sent should a client attempt to delete it in minutes.
     * @type {number}
     */
    const KEY_DELETE_TIMEOUT = 6 * 60;

    /**
     * @private
     * @desc Indexes of each dual-symmetric encryption mode.
     * @type {int[]}
     */
    const ENCRYPT_MODES = [
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
     * @private
     * @desc Symmetric block modes of operation.
     * @type {string[]}
     */
    const ENCRYPT_BLOCK_MODES = [
        'CBC', /* Cipher Block-Chaining */
        'CFB', /* Cipher Feedback Mode */
        'OFB', /* Output Feedback Mode */
    ];

    /**
     * @private
     * @desc Shorthand padding modes for block ciphers referred to in the code.
     * @type {string[]}
     */
    const PADDING_SCHEMES = [
        'PKC7', /* PKCS #7 */
        'ANS2', /* ANSI X.923 */
        'ISO1', /* ISO-10126 */
        'ISO9', /* ISO-97972 */
    ];

    /**
     * @private
     * @desc Stores the compressed PGP public key used for update verification.
     * @type {string}
     */
    const PGP_SIGNING_KEY = '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';

    /**
     * @desc The Base64 encoded SVG containing the unlocked status icon.
     * @type {string}
     */
    const UNLOCK_ICON = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwI" +
        "DI0IDI0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMTdjMS4xI" +
        "DAgMi0uOSAyLTJzLS45LTItMi0yLTIgLjktMiAyIC45IDIgMiAyem02LTloLTFWNmMwLTIuNzYtMi4yNC01LTUtNVM3IDMuMjQgN" +
        "yA2aDEuOWMwLTEuNzEgMS4zOS0zLjEgMy4xLTMuMSAxLjcxIDAgMy4xIDEuMzkgMy4xIDMuMXYySDZjLTEuMSAwLTIgLjktMiAyd" +
        "jEwYzAgMS4xLjkgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6bTAgMTJINlYxMGgxMnYxMHoiPjwvc" +
        "GF0aD48L3N2Zz4=";

    /**
     * @desc The Base64 encoded SVG containing the locked status icon.
     * @type {string}
     */
    const LOCK_ICON = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwIDI" +
        "0IDI0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZGVmcz48cGF0aCBkPSJNMCAwaDI" +
        "0djI0SDBWMHoiIGlkPSJhIi8+PC9kZWZzPjxjbGlwUGF0aCBpZD0iYiI+PHVzZSBvdmVyZmxvdz0idmlzaWJsZSIgeGxpbms6aHJ" +
        "lZj0iI2EiLz48L2NsaXBQYXRoPjxwYXRoIGNsaXAtcGF0aD0idXJsKCNiKSIgZD0iTTEyIDE3YzEuMSAwIDItLjkgMi0ycy0uOS0" +
        "yLTItMi0yIC45LTIgMiAuOSAyIDIgMnptNi05aC0xVjZjMC0yLjc2LTIuMjQtNS01LTVTNyAzLjI0IDcgNnYySDZjLTEuMSAwLTI" +
        "gLjktMiAydjEwYzAgMS4xLjkgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6TTguOSA2YzAtMS43MSA" +
        "xLjM5LTMuMSAzLjEtMy4xczMuMSAxLjM5IDMuMSAzLjF2Mkg4LjlWNnpNMTggMjBINlYxMGgxMnYxMHoiLz48L3N2Zz4=";

    /**
     * @desc Defines the CSS for the application overlays.
     * @type {string}
     */
    const APP_STYLE =
        `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`;

    /**
     * @desc Contains the raw HTML used to inject into the search descriptor providing menu icons.
     * @type {string}
     */
    const TOOLBAR_HTML =
        `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`;

    /**
     * @desc Contains the raw HTML injected into the overlay to prompt for the master password for database unlocking.
     * @type {string}
     */
    const UNLOCK_HTML =
        `eNptUc1ygyAQfhXGTo6M1t6M5pQH6CssgsoUgYE1qW9fUDHGqYfV+Xa/H3drLh9E8ibjLR3Bo3DUPIRTMGekVeD90knQjdSH+Q2lrdCB10mh+D+k97bHWYkmQ2Mr8lVcgiKphzLBrVHGVR9dV4TnmiWjQQAPwbZ8o++zW50PZeQyl9+WEr69BZ0o1pnR4okSB/Zpqe2EBGcbfG3I/DTuLX7C6JZ8E+aMvqZRYox9BwQGXpDv1MlTNrJubJP1CEhioQxc/Pc9NGnI4QRxZPLZkRYZ1AFK3e9bfEqOQ0XCphajPDidDIOkm1RQBCV7vRMtcB6EaDxDWdjf65qFTYhGH7grcPL7LIrL6zaTVqb9oXxbAWWoj2nW11r/ADMvzfQ=`;

    /**
     * @desc Defines the raw HTML used describing each option menu.
     * @type {string}
     */
    const MENU_HTML =
        `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`;

    /**
     * @desc These contain all libraries that will be loaded dynamically in the current JS VM.
     * @type {LibraryDefinition}
     */
    const EXTERNAL_LIBRARIES = {
        'currify.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"eNqdVFFv2yAQ/iuONaWgEit5jUujae2etvZlfbKs1rWhYaLgYWgWOfz3gcFOKuWh3Ys5HXcfd9995xk1otZMCiBgzyhI5fNvUusUY71viaQJ+dtKpbv5PDWiIZQJ0qSz8fJVNoYTGI4shmIBYE54RxKPN+IfEQPKfB7OrHptYDBBUSIRUntOdKJyoPC5Z3dMNHK3Ccf6XMQLl88V34TjbERHON34z1pvWQez2ijF6N4Xby2YWIH9W6USgRQiuSLaKJGMd4kAzos07CePBBSZgccZKWgZLDVYHqbGZ+hQ5I9hyvERjdznmPm8hvG92oHOltD72ehj0edRORZkl9wqJRV4+lYJIXXimm3idJKLLz21F08w11sldwnPatkQnP68v3n4cft4d//r8fv9w91Nirj1cC32peM+TnPdW5v7FoplmdUV56AdB41OteNTCR4CV2UhypEtCcjhIKBFLTomDnw65mwM8i+Ol0MR7ENMUdexF4rAy1xc6YwT8aK3ubi8hBJoVwScqrCgjxNeF8eyfRmwT43TaqcVc7ofGNX4dMawDyDFabsRV2VV2/I9eJOsSZaoUi/mlQjduX5PXiGfjfei+mwGkv+Tg9gHskqbn0g8/iim+UwrJWBQWJBiSkXSbaXhTfJMpqWZpW7o05/iPc1+nEFG09txpIjhr0pVe0CuVxuyWK2XEFG8yumVE4GbNivoYlUe05yc/LpIh4pYxLjGKlrwfMMsrJM5VkXARI54H1sotwxS1JUGDA2lZa2SWnomso6zmoRdOZIIHfn1VMJirGqxQnwUqQYGFnV5OBhrUe9Ydx9UpFG3aQnBZEML838pAQw+"},
            'curve25519.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"eNrtXAtT20i2/ivMVNZlxQ2r7tZzjJiChLyZZDZhixTlsMLIRsFIHsuGkMD89vudPpItvxJmJnu36t5NSm7163ynzzl9+il+nBTJRjEepd3xj+3+ID+NB1uPJqOrRLmuDKPuIC6KjdGXYhyP0+7GSZql45Nhnmbj5sj60s2zYrwxjrLkeuPJII/HnrM7GsU3TelZ7bSHIr181Bwk4408stv59mhrkGT98Xk7b7Ws8XHeiUb4aY+S8WSUbYzvKpR+z25aX8rk0VYd1aoVkusKHcvOrJxU0vPctUVdT6pQ1Co8XltU20GghRO6WsgwlI7Qtgx84bqO5wvp+bYrlKfxKpVwQ9ehAm7gIstFlvZsHQrPlfiV+BcK5QeBJ5Qdhm4NXq3F96QPamFoe0KHgQoEKPqOcFzEhNaOlMJVSFDKEa52XSU8KX2JLFvaQHaQ4PiORgEFJlzX95UIEZmhH62Xk4N2ohGegwZJT3rClUTRUaG2hQ5kAHRpOzZkEBIDniMJD4wK1w8hACfUqKWkayNFuaEtpGNrVwSuq2ccvF/LgfKUTdQVJP9v+J2x8HwtCxCx9oQMQhfCD1202HZQ3w2cIBCOo9EaD+0TkpQKASsb1uAGZB5kNNKG/lyf8hQq+iLUMBLYgg5n6N3zpHthutG7m2FSgBfqQKN21ZXG6Erj7XjUn1wm2bioutQYXQpd7sfj/PRj0h1vHILhwJDp/PhDFDVH0WuTsTUc5eN8DNJb4/wtOn7W3+rGg0FzSvF43LEsa3w+yq83qGcTG/ujEeD/NcmST0MQSc42iMLGgy+jO7FBLmQG969ZS0Y3w3F+cpWM0t7NiVbNkRiLXGTWl94k647TPNtIqzSRcjsTUaB91NYEYbKdthM0rLiFpxi3ks6H/DhDULqMpmwUm3JnZyewNuVdqbIZSa2mrBTJ2Dg0ymOg3ICwX5Ke8UjkjCL7lhzTrN5gWk/kXDNrs99Lo9+b+aa02vNOriSWRWmjSRQ/ED1LmNcoE2MOK4Bh3L1gBEN/KpiM/KtRNzUlkgaEVQ8AUnZOIum0spaH/uOizEE8Pt/qDXJq1t8p0SPUcSfKN03sYdYeHdudVpRtypb2HzYRWneEkQqIvWxVL1pwuCJeTDG8pOAlJV5S8BIfp4DBj8nKmrElZj+sSGUU+YXye+AiivFDfKEXpGgeSLmGVI9IET3DtLuJ0umm7OzsSK8hLcGxRmQy271j6VJp/G5q5Xs+FUdXrkoXkSnBUWGyyqpitDXVbSx6Qm4W1t1Su8bH6iHYQbEGsSRMvCWZQZjdTIujUonVoJibQXHWK5owxvbUqcy0nsMehWzkkEZFbJLNsr9prsRR3mk1TQjOtrcD4FCjG5GRSEX1dJB3L+Kzs8qSK6PNQDIjkpkhmRHJrNNCP+vMVS0mp/erurlUdZRPsrO5HiRSsgrq6qKHJ8bTxTPBM8BzgucczwWeIZ5TPDd4zvBc4+nj2cVziWcPzwGeQzxXePbxvMPzEs9bPE/wPMfzBs9jPK/ANKvoY0RSF0cIZEe8R6A64hEC3RGvETgd8QmB2xGfEXgd8QCB3xG/IQg64imCsCOeUXWQeUEh6PxCIQj9SiEo/YNCkPonhW4HvSBqZhCU3bEefhQFeuPDI9Gj4L2IKXgkuhS8FhMKPokBBZ/FCQUPxDkFv4kLCp6KIQXPxCkFL8QNBb+IMwp+FdcU/EP0KfgnARlYaWB7DBszbJdhJww7YNgThj1n2AuGHTLsKcPeMOwZw14zbJ9hdxm2V8IqAxszbJdhJww7YNgThj1n2AuGHTLsKcPeMOwZw14zbJ9hdxn2kmHjElYb2C7DThh2wLAnDHvOsBcMO2TYU4a9Ydgzhr1m2D7D7jLsJcPuMWy3hHUM7IRhBwx7wrDnDHvBsEOGPWXYG4Y9Y9hrhu0z7C7DXjLsHsMeMOykhHUN7IBhTxj2nGEvGHbIsKcMe8OwZwx7zbB9ht1l2EuG3WPYA4Y9ZNhBCesZ2BOGPWfYC4YdMuwpw94w7BnDXjNsn2F3GfaSYfcY9oBhDxn2imFPSljfwJ4z7AXDDhn2lGFvGPaMYa8Zts+wuwx7ybB7DHvAsIcMe8Ww+wx7XsIGBvaCYYcMe8qwNwx7xrDXDNtn2F2GvWTYPYY9YNhDhr1i2H2GfcewFyVsaGCHDHvKsDcMe8aw1wzbZ9hdhr1k2D2GPWDYQ4a9Yth9hn3HsC8Zdli5C3ZTp4x7w7hnjHvNuH3G3WXcS8bdY9wDxj1k3CvG3Wfcd4z7knHfMu5phct+6oZxzxj3mnH7jLvLuJeMu8e4B4x7yLhXjLvPuO8Y9yXjvmXcJ4x7U+Gyozpj3GvG7TPuLuNeMu4e4x4w7iHjXjHuPuO+Y9yXjPuWcZ8w7nPGPatw2VNdM26fcXcZ95Jx9xj3gHEPGfeKcfcZ9x3jvmTct4z7hHGfM+4bxr2ucNlV9Rl3l3EvGXePcQ8Y95Bxrxh3n3HfMe5Lxn3LuE8Y9znjvmHcx4zbr3DdavjTwcOmAXxv0WhBUQP8yCIvTlHDwGuLvCtFDSOfLPJ6FDUMfbbIG1HUMPbAIi9BUcPgbxb1XooaRp9a1Ksoahh+ZpG1U9Qw/sIiI6SoacAvFtkGRU1DfrVIZRQ1DfqHRZKk6CvTPprson3NhBONPI8sq4VZpbR4om6Vk3Ek1SbsWTlhpykrCBSt9H6le1S6d9/SMZWO71u6S6W79y09odKT+5YeUOnBfUufUOmT+5Y+p9Ln9y19QaUv7lt6SKWH9y19SqVP71v6hkrf3Lf0GZU+u2/payp9fd/SfSrdv2/pqcmn5boS4X9t/r82/3/a5uetXdDGSpQgkJ2oQKA6UQ+B7kQxAqcTdRG4nWiCwOtEAwR+JzpBEHSicwRhJ7qg6iAzpBB0TikEoRsKQemMQpC6FmZ9H/WXF9knZ0kx5p2k0VZt7U2bSPl0MyzNrmpbTrwYzpY2eczG0PJWTza31ZNGytXtdIdKbG5adVDmJROZJdQPUZQ2Gg4Hc5whH0y0V+y8AIawFjYTi248iEeXk4FpJu0lVptxy/st8ExLJxOBzS0rRK/cBlja3oITWEyZLKUMllJOllLOV26c9Wh/c1vLdo92bI97JM1eKc1jDb1L5Tdyerv1HJHCsBqRcgIx2qpvDCUkVyYFiRGpLpFK8CMG9BbTz4R+eDuV9tuiAf1I1FOu0+6R1jY3e1YRgY2dnR3dwU/Tb/SshpzfH+uKwqqnTMSAU6a7SiciFpNpCm0WxXMpVGYCOoO5Mt25lJrZDMTJquRzEc8nA2WylEY4J3+IuxpEt0aOClJTz1eAQrXVydIcFBEeLDE0WcH4Mt0BGE9WM3Vi3UcjNQMrrQIG0ZIem4OgiFZsFibiwPt0q4jnkIHAFLlfXETJFgQQT3vTsJ5AJ3zT7cypQ7kQFwtNGoohp9U3uoeWsBf69XlcnE/3F2ub4NWJAW9k7+wopwEqtK9N27C52dmtEpRJCKZxzTu3uYmgcdlcddck1Kp7JmFW3efq2d3yacXM68BTS0+7yrEDOuELfc933ICOiELH8R1HCs9WQSh95QptO6FW2qEjudBznMDRYYhXJW07dH0tlPS1Cl0XvT30ZBj4IC1AWXoqcHwlpGsHIR0faTpZ1IF2lOcK5WBM0q6PWirUYEC6fihU4Nu+p5WS5tAOrLmejVfl6EDagS2Ur50g0Dp0hJa2GwaOLelkzwlDPiq0faVc5aMxYNqToOYICcQgINaEdkObWoT6MlSu7QeaDsFsL5CBAm9ojaeQqmxPhKHUICGR6EmgggMtPK0DW2sJUvBvCmDgCtIJfTTFgzgD7erQJraUh39Sk2QdGyWVgzKCJGwOz5DvoCLABMQrlad8SNOznQBMKyTayIKMtRa+b0OpIdiTTuiGoR1Sq5UTQrZSQcSBC1pSaRfSdl2SfaggIN9VMoAg6OTXs+lYk44ywyBEEe0L0HSUsoMAZcMw9CWwSAeopMFaKHzP80nCqBW6CjQCGIxy4T9CJ4C6NIxAS+2RbShIRfvQl0DouT6MCTza2nFccI9UN3Bc6FdCMI7ngYBpBAShPGMbvhto5ZEOIGLl0HmlkB4q+KH2BESpoVubznGhCR/MOJCLJrYkGRmMBUgaelWh4+PNmJ5SgQ3LRC0YL1SsQmnkHhAGxEnnoRAFHdGiyTAcTSe8kBM0Z7vUAOmQ2sj0JKkBNmtOSj3fDWFXZMceGSnEiabaPlTnk5VCjS76CHFjB54GdyRY2J6iE28tSRoOykFwboji0DREBIt20Tt8Ohh3Ybq+Tyx4gLapq7oSWnQDMj68IIlOYvFqg/PAJkPXCn0WTMDiQlCQMBWkej7UBJ2BMYBqqhW46DUhBCoc8ESmZ3qUDanAaoRrk4bowBzqBYvoPa6A2oHqkop9FAhgklqgN8J0Ah88+QEaAMdhixAVNLwDHeNDvraPplKPVNRjJPUSzBcgcXQo6ZL4IVBNFq9hMCEp3ndAU/tkZPBFtvbgm6AYWLdHXQnVfOoIMH9Ug0whb0m2Qf1EhdR9TKNgEygAl4QuqdGnyScEcHzKEQ548mE0kIoDT6XploFAi7zQiBWi8iAUuiuhfbRCAoUsHl1bS4d8FboMNEIuUMMBQkgqNC0DAza1F51Jwjg8unMBjmBzoVEyrNLzwZNAR4KwqEfAn9GtDI8uScAuIHwX+oClwHRsKurYkBF1UmW8nQyIWQkLlDqgKw6QF1rtwOBgU7BcWDIZXEjOivQFCYJbG/QdutGBjmbaAl8HwxBQJZwSWincwHfQzdHhICXYd2gMMPB8NIC7A0zJMw3FqsIhiyGhwwRtcoSK+hgNJ7AbFZCjhINDk+wQXEoaYuCwyMrh9mGIjmtTV0M3hBSAAVbM+OE7Ho1GaCgaTTYIj0H+IJSdcnr8PBtrNb22g7X4cqKZMfcEzTponnEizsUFxvVTcSPOxLXoi11xKfbEgTgUV2JfvBMvxVvxRDwXbyJaGInHES2MxKuIFkbiY0QLI3EU0cJIvI9oYSQeRbQwEq8jWhiJT+aATHw2B1bigTlAEr+ZAx3x1BywiGfmwEO8MAcQ4hdzICB+LSe77WwH0+igzWeVh0g9pAnRISZEV1Hw8LD1K2Y8hzTzvmrZne1t5dzSKx2fSs+8KjpJNW+ALKqyzqysOyvrTcv6PI9nwMA2gGkPM7I3Io4eY2HxCkuJj1g8HGG58B4LhEdYi7/GzOoT1s2fsRp+gDXub1i5PsV69JnYjV6Iy+gX8ZLPrBvNd9EvlngbvduhiYt4UiXvR68t8Tza5+SXrVnx5lNKc26PwGxgfeBoYKIOokeIhrdP0SiNWezb1pRya0baFAKJpyWJIybxtCTx1JA4Kkk8b63i4mnj2YffnzZerIM4arz/8PtR49G6+umxgs5kZ119k9+p197HSujwb5j4Ug1QKDhmLdTdr1VBIm0IN6fA77h0Waemg4Py9eXtW7KB1RrZK1+f3NJG8hMmxcVXa+oT0lRw+2Z7m8T6hmK3n7a3tV3GfIopd72e3jCBT0zAkCNqhsAnQ+BNSWDWaJbOp8bnD58aDz58bjywlgm/aTz+8Kbx6sPjxqt61YuqxNcFZy22HxY9J766ZM9Wy3JSkxlzfLCCz706d4+jHvxNDGfThaeZ/Fle30cDuKYT+KVzOLMLeKQh3NEpfNENHNHZQkueRddwSH14o124sEtBNhdF0jXXIK/gFK7IC13BKZB9XnXqTS8QX9H6/VnLqU7zqhVaxq7rtlPM0ldaR93M95iKXKbSbB4wJc4zIrndgwFJGNAB3bKimHLKmG9iX7HHPUPgoCSwZwgcMAGK+NYKrhyr1mlnDDkzjkKClbqkqEIDULLkGZY8y1rHjSktq+LK0NLMjldnB2/fMhUuSFqcdvTnxgiKWVJpF+2amj+ttvA3Vl3PZtBkGZiLIl9R5705NTuUbxZ4JerRp/X98fNqbh8vcCtn3MrvxS1W94+XuEXi5/XcPljN7asFbtWMW/W9uFWd6NUSt0h8sJ7b31Zz+3GBWz3jVn8vbnUn+rjELRJ/W8/t09XcHi1w68y4db4Xt04nOlriFolP13P7bDW37xe4dWfcut+LW7cTvV/iFonP1nP7YjW3jxa49Wbcet+LW68TPVriFokv1nN7jxnoPs/iK27978Wt34leL3GLxF8WuP21RbN/kW1SUN0Lzu54z25p1ROsWPQEtLm+cKKg3HIlFJc7pN2Ib2UmZlcdC2ws0rCmw6AAP4WVLVaUtDBGHJ4A6z3azMLCEnHamaR9ArM/hTisWWo3xCKTvgtIyF5oIUibLFheJ6QR2vDRjqddRNFk6TrSwfJYuRhwAO/YQai0S7sQBcHTmh0V3JDyAQ9GpPSRrxHXVD/Est+mbx8KglchcunjBB9xwPu0VwtmKNuj6tLVWDY6lA14jUUxlup2KNJmIgqzbyvyvxmxx5joxNt5Oza3eWO6FdrdzFsxr416dGuVivWOm3kEmW4i8rCZb2Pt+7P8ybaszbAT2SJr9kS+GYju313tBb4dSnVriy6N1yVmjzAZLDBgtF0cPIwhoJjWbHFnukU93W2mHfqvnXqJdCklWUopllLucWn6z50qtWsnEZkZAM2YPXdCMRDmAmteT58drg3mTidSU90QmksfmOqG0AKNVKRL5xmJGS4E3ZRdykmQQN+wLGQUZjwUdMd2DriAIou55vQAmC2c1RS1YxGq1V1KmczVKk89qUm9pZMXI8WJ6C4lg7/uitKaiEys+o39v2xD7dqhSTIvlUp1RiHJkjaMrpPFE5XUIpXIzoeI0svL6BnWMNP738sHp7VjjTJl8cjXMUextVMmOpUVdPiL0nfl5xqmPJUZV2XAN5prPuLiM6ppjixz5FKOWpuj69QKOpJpF3xyWVjMOTz6cfH34NbumOPLwqKr/6MtMgtzvZ5fx/RaVrDmpXIaF8m8So8XNfgH4512rQ0ZS+RooWkZi+P9UvKCLOpWwdI4MoBVxbpis9ox/2V+9oo/IKh/kjB3Gn6s6OzCnCO4IlRC0VGNkIEIAkEfRknXQxZ93KZoF1jQvq0JbfH1/7Raa0+v+pdGkkaeuSugFZSX8t5cBlefROmmVtBtirGgnWwX7VYrscbHCX+r4j0ks3uYHyebTSpowfoik4uRA4tKQe+bNJQ8zNplLWHuD9h3Mwj6BkXzRygV5abpMjs7jkXEK6oVxYYxtdmXSLXKm1FmatS6CnLLawstCeJj/j4Ec5by85Fx7SrDKDmbdJPm1xTjOaX42mUL2tm255gPLfLqQ4vlLEpFfLRlVD+u2UJ3+knnSZH2s2b5zRV6wswNFM3pl1j1mVJtBgSuyqnSfGK1PzydF61qD4a7v96rZufbmTnexmTVadWvUJS3K1SZqxXlplXuaKt+3Iwxaf6EO2vR72irVFAx617GQ0x4pCoHgEl1/2IKxofrKYOuwMOwCQgSxRQiqYhAg9NLHPZyS0x6sbKR5nKHmQUhIeaymGy1zF2QhymmQbODeraL+UZ3LcPU7JS7V7cO1ugqpS9PkCtLiEW3tITJaksYfCdLMNsXynUw25Kz9o9pzln13TnJGHuISUXlZJRzszITphSTKc1lQjGcS0Ki/KTKn1duzygXHqmm3d6CAQ1Er2ZAg2r2OuN7ZkDxGoNdNKCiIrLEp73ciMnxQnqJbNJ78+0usyihS59MUUKXy7a6sC6aX8O6ul+1rpLbSWli1YWrFcbU/U4mYb6VJR9I/I7Mp4kjEumo046nV6li8vsNumjFr7eR58xrqpwHGk3Fi/1latzQdiM+9nTHmP2gksQgSn6uOhFWI9ZPlWeNaZaG4rfRRAymrjnPrpLR+M3kdJB2XyY3X/+GUPzJ6Walo/odsownR7XFQbY88aAJeLKQMZ26pjTxXFouLMxOcyqUrxmJTvJhks0GnqkTStalzV0PmpuzrRBWes+vMEtJzBJSWltOO9/sC+YMc5tU2Nbd/OT5O9yitL95i1L+qeuT1VD+H13EVhJfP+Gv26VZJ+Sr7sH15leu1U26Hq05F2y2J3pmyblwOc8Ax9+6+FdLXl4oDlYsHhNR+vaFtXDMmxXJiqw1xb+ZZtZXyWpmi/ndgWrpXQjzLXYBzAX7KXcDzPrk+eJy4740f96UPzVr605TPoqinKfX/hST9DK3PFxF2qz4arsUNq806xd2V/T07qpB5TvMOL/LXCXtNWmObnE/2JSUQLOB1JolURemP31QYDpSmB5ckIcoOrUcDGllVjlRKAzt+UlClyYJtRlCd2GRSDc4uksTk3xukKvWzBPe+uFh0AzjmzxULjnGHI4xhq54VbfUELtdNfRuXUPp/mnlKTC1vKtmngBbHCHTqUspePimgTinkVWYXx7aqyGksNbeIT9ZXvmvHzBoGR+Fs8Yv7agwy6NJd4wmWl/G52mxVVysslaTNVyVdddPag0dzf4Qyc97k14vGW31Rvlls6xvTf+EB0r+tKqAITdKr+Jx8k16xbfoocBdMUfPSG5NOzGiFhfTKRdep3MufqdJ1+opW8k8Tdzs2dixTnlcWFQcVi9T5Co+ha8lmIlfBTctkH9D1vlaWWfJiCVTsGjQOX8oi6YFv6B2o/GDERHSWFR5/c+t8J9a+fEyKYq4n2xcTmCWp8lGvHFq6v9o/rKSpk8qmksTxDpbIGqVfxxmmfqQdbhxkdxMEbTaOL0ZJ8WP1lfUUhi15PgR/2k1jb+hpvEaNXXzy+FknLxNumC62vqETMfRoqrG1u3tvKbG1s9LZv7TV5RAVmAmkgt/1Gc8E4RR5Xitpq5HedbfGBqXYNTFBWtmUFL6BoXCNHeewvpPZ76iTzpDYESaNGdzSkhr4s/mxZ/Cd5Q7T0baK2Qyo/rDsiaWOs34D3ea8de6C8iJvyhOQOSNxoqWYS7r0cdPeUV0HdVRnJ3llxtn8The1NLSyNTMf8aw9xOmFa2p9bSBvbDTh6WNqPKnisvX6p72cOZ7f1r9hamR+V5pROuK0XSkXlAxTwjKL9AqEyoTV3VGwZuUYPSAVbfeb/7vmMA9uupfso81tr9kId/BQGAddcuYduj7GYioSyabzQ5tMDoja92t26uol1oPnq8An4eGeZRWNbUQTDlGN1/mDXBqJqMt2lGoyq62ObDdjcfd89l86Ad5d1evN66Z7z3oVRPMORJ/0ZCH1Szwz5ryv2fm8a05x4oeZA7h/vQwt8a6pz3F7H+t3FXK6KvXqXFNrTDdtn/OJoPB3PCUTXU4c2HlvOD/mwKXYLNl2OwPw2Zfg83W2I3ZlzOOMfuWv4XWY6g3WTE/+tNGt2J0bM3sLvla7sIgiqXO/PA5n50vjLHmW8y8NsyusfBEpCKdWfhOZN/difLvPPZGSfI5aS79TVer/T8DsSy2"},
            'openpgp.js': {"requiresNode":true,"requiresBrowser":true,"minify":false,"code":"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"},
            'sha3.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sjcl.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"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"},
    };

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
            /* Do this as early as possible. */
            _self = this;

            /* ============================================ */

            /**
             * Discord class names that changes ever so often because they're douches.
             * These will usually be the culprit if the plugin breaks.
             */

            /**
             * @desc Used to find the search toolbar to inject all option buttons.
             * @type {string}
             */
            this._searchUiClass = '.search .search-bar';

            /* ============================================ */
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
                    _self._checkForUpdates();
                }, 3600000 );
            }

            /* Block tracking and analytics. */
            _discordCrypt._blockTracking();

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
                        _discordCrypt._saveConfig();
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
                        _discordCrypt._saveConfig();
                    }
                } );

            }, 5000 );
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

            /* Remove all hooks & clear the storage. */
            for( let i = 0; i < _stopCallbacks.length; i++ )
                _stopCallbacks[ i ]();
            _stopCallbacks = [];

            /* Unload the timed message handler. */
            clearInterval( _timedMessageInterval );

            /* Unload the update handler. */
            clearInterval( _updateHandlerInterval );

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
            _configFile = null;
        }

        /**
         * @public
         * @desc Triggered when the script has to load resources. This is called once upon Discord startup.
         */
        load() {
            /* Due to how BD loads the client, we need to start on a non-channel page to properly hook events. */
            if( [ '/channels/@me', '/activity', '/library', '/store' ].indexOf( window.location.pathname ) === -1 ) {
                window.location.pathname = '/channels/@me';
                return;
            }

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
            _discordCrypt._injectCSS( 'dc-css', _discordCrypt.__zlibDecompress( APP_STYLE ) );

            /* Reapply the native code for Object.freeze() right before calling these as they freeze themselves. */
            Object.freeze = _Object.freeze;

            /* Load necessary libraries. */
            _discordCrypt.__loadLibraries();

            /* Hook the necessary functions required for functionality. */
            _discordCrypt._hookSetup();
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
        static _getDefaultConfig() {
            return {
                /* Automatically check for updates. */
                automaticUpdates: true,
                /* Blacklisted updates. */
                blacklistedUpdates: [],
                /* Storage of channel settings. */
                channels: {},
                /* Defines what needs to be typed at the end of a message to encrypt it. */
                encodeMessageTrigger: "ENC",
                /* How often to scan for encrypted messages. */
                encryptScanDelay: 1000,
                /* Default encryption mode. */
                encryptMode: 7, /* AES(Camellia) */
                /* Default block operation mode for ciphers. */
                encryptBlockMode: 'CBC',
                /* The bit size of the exchange algorithm to use. */
                exchangeBitSize: 571,
                /* Default password for servers not set. */
                defaultPassword: "⠓⣭⡫⣮⢹⢮⠖⣦⠬⢬⣸⠳⠜⣍⢫⠳⣂⠙⣵⡘⡕⠐⢫⢗⠙⡱⠁⡷⠺⡗⠟⠡⢴⢖⢃⡙⢺⣄⣑⣗⢬⡱⣴⠮⡃⢏⢚⢣⣾⢎⢩⣙⠁⣶⢁⠷⣎⠇⠦⢃⠦⠇⣩⡅",
                /* Decrypted messages have this string prefixed to it. */
                decryptedPrefix: "🔐 ",
                /* Decrypted messages have this color. */
                decryptedColor: "green",
                /* Default padding mode for blocks. */
                paddingMode: 'PKC7',
                /* Internal message list for time expiration. */
                timedMessages: [],
                /* How long after a message is sent to remove it. */
                timedMessageExpires: 0,
                /* Contains the URL of the Up1 client. */
                up1Host: 'https://share.riseup.net',
                /* Contains the API key used for transactions with the Up1 host. */
                up1ApiKey: '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs',
                /* Current Version. */
                version: _self.getVersion(),
            };
        }

        /**
         * @private
         * @desc Checks if the configuration file exists.
         * @returns {boolean} Returns true if the configuration file exists.
         */
        static _configExists() {
            /* Attempt to parse the configuration file. */
            let data = bdPluginStorage.get( _self.getName(), 'config' );

            /* The returned data must be defined and non-empty. */
            return data && data !== null && data !== '';
        }

        /**
         * @private
         * @desc Loads the configuration file from `DiscordCrypt.config.json` and
         *      adds or removes any properties required.
         * @returns {boolean}
         */
        static _loadConfig() {
            _discordCrypt.log( 'Loading configuration file ...' );

            /* Attempt to parse the configuration file. */
            let config = bdPluginStorage.get( _self.getName(), 'config' );

            /* Check if the config file exists. */
            if ( !config || config === null || config === '' ) {
                /* File doesn't exist, create a new one. */
                _configFile = _discordCrypt._getDefaultConfig();

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
            let defaultConfig = _discordCrypt._getDefaultConfig(), needs_save = false;

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
            if ( _configFile.version !== _self.getVersion() ) {
                /* Preserve the old version for logging. */
                let oldVersion = _configFile.version;

                /* Preserve the old password list before updating. */
                let oldCache = _configFile.channels;

                /* Get the most recent default configuration. */
                _configFile = _discordCrypt._getDefaultConfig();

                /* Now restore the password list. */
                _configFile.channels = oldCache;

                /* Set the flag for saving. */
                needs_save = true;

                /* Alert. */
                _discordCrypt.log( `Updated plugin version from v${oldVersion} to v${_self.getVersion()}.` );
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
        static _saveConfig() {
            /* Encrypt the message using the master password and save the encrypted data. */
            bdPluginStorage.set( _self.getName(), 'config', {
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
        static _saveSettings( btn ) {
            /* Save the configuration file. */
            _discordCrypt._saveConfig();

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
        static _resetSettings( btn ) {
            /* Preserve the old password list before resetting. */
            let oldCache = _configFile.channels;

            /* Retrieve the default configuration. */
            _configFile = _discordCrypt._getDefaultConfig();

            /* Restore the old passwords. */
            _configFile.channels = oldCache;

            /* Save the configuration file to update any settings. */
            _discordCrypt._saveConfig();

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
        static _updatePasswords() {
            /* Don't save if the password overlay is not open. */
            if ( $( '#dc-overlay-password' ).css( 'display' ) !== 'block' )
                return;

            let prim = $( "#dc-password-primary" );
            let sec = $( "#dc-password-secondary" );
            let id = _discordCrypt._getChannelId();

            /* Check if a primary password has actually been entered. */
            if ( !( prim.val() !== '' && prim.val().length > 1 ) ) {
                _configFile.channels[ id ].primaryKey = _configFile.channels[ id ].secondaryKey = null;

                /* Disable auto-encrypt for that channel */
                _discordCrypt._setAutoEncrypt( false );
            }
            else {
                /* Update the password field for this id. */
                _configFile.channels[ id ].primaryKey = prim.val();

                /* Only check for a secondary password if the primary password has been entered. */
                if ( sec.val() !== '' && sec.val().length > 1 )
                    _configFile.channels[ id ].secondaryKey = sec.val();

                /* Update the password toolbar. */
                prim.val( '' );
                sec.val( '' );

                /* Enable auto-encrypt for the channel */
                _discordCrypt._setAutoEncrypt( true );
            }

            /* Save the configuration file and decode any messages. */
            _discordCrypt._saveConfig();
        }

        /* ========================================================= */

        /* ==================== MAIN CALLBACKS ==================== */

        /**
         * @private
         * @desc Loads the master-password unlocking prompt.
         */
        _loadMasterPassword() {
            if ( $( '#dc-master-overlay' ).length !== 0 )
                return;

            /* Check if the database exists. */
            const cfg_exists = _discordCrypt._configExists();

            const action_msg = cfg_exists ? 'Unlock Database' : 'Create Database';

            /* Construct the password updating field. */
            $( document.body ).prepend( _discordCrypt.__zlibDecompress( UNLOCK_HTML ) );

            const pwd_field = $( '#dc-db-password' );
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
                    unlock_btn,
                    cfg_exists,
                    pwd_field,
                    action_msg,
                    master_status
                )
            );
        }

        /**
         * @private
         * @desc Performs an async update checking and handles actually updating the current version if necessary.
         */
        _checkForUpdates() {
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
                        $( '#dc-old-version' ).text( `Current Version: ${_self.getVersion()} ` );

                        /* Update the changelog. */
                        let dc_changelog = $( '#dc-changelog' );
                        dc_changelog.val(
                            typeof info.changelog === "string" && info.changelog.length > 0 ?
                                _discordCrypt.__tryParseChangelog( info.changelog, _self.getVersion() ) :
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
         * @desc Inserts the plugin's option toolbar to the current toolbar and handles all triggers.
         */
        static _loadToolbar() {

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
            $( _self._searchUiClass )
                .parent()
                .parent()
                .parent()
                .prepend( _discordCrypt.__zlibDecompress( TOOLBAR_HTML ) );

            /* Cache jQuery results. */
            let dc_passwd_btn = $( '#dc-passwd-btn' ),
                dc_lock_btn = $( '#dc-lock-btn' ),
                dc_svg = $( '.dc-svg' ),
                lock_tooltip = $( '<span>' ).addClass( 'dc-tooltip-text' );

            /* Set the SVG button class. */
            dc_svg.attr( 'class', 'dc-svg' );

            /* Set the initial status icon. */
            if ( dc_lock_btn.length > 0 ) {
                if ( _discordCrypt._getAutoEncrypt() ) {
                    dc_lock_btn.html( Buffer.from( LOCK_ICON, 'base64' ).toString( 'utf8' ) );
                    dc_lock_btn.append( lock_tooltip.text( 'Disable Message Encryption' ) );
                }
                else {
                    dc_lock_btn.html( Buffer.from( UNLOCK_ICON, 'base64' ).toString( 'utf8' ) );
                    dc_lock_btn.append( lock_tooltip.text( 'Enable Message Encryption' ) );
                }

                /* Set the button class. */
                dc_svg.attr( 'class', 'dc-svg' );
            }

            /* Inject the settings. */
            $( document.body ).prepend( _discordCrypt.__zlibDecompress( MENU_HTML ) );

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
            $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );

            /* Handle clipboard upload button. */
            $( '#dc-clipboard-upload-btn' ).click( _discordCrypt._onUploadEncryptedClipboardButtonClicked );

            /* Handle file button clicked. */
            $( '#dc-file-btn' ).click( _discordCrypt._onFileMenuButtonClicked );

            /* Handle alter file path button. */
            $( '#dc-select-file-path-btn' ).click( _discordCrypt._onChangeFileButtonClicked );

            /* Handle file upload button. */
            $( '#dc-file-upload-btn' ).click( _discordCrypt._onUploadFileButtonClicked );

            /* Handle file button cancelled. */
            $( '#dc-file-cancel-btn' ).click( _discordCrypt._onCloseFileMenuButtonClicked );

            /* Handle Settings tab opening. */
            $( '#dc-settings-btn' ).click( _discordCrypt._onSettingsButtonClicked );

            /* Handle Plugin Settings tab selected. */
            $( '#dc-plugin-settings-btn' ).click( _discordCrypt._onSettingsTabButtonClicked );

            /* Handle Database Settings tab selected. */
            $( '#dc-database-settings-btn' ).click( _discordCrypt._onDatabaseTabButtonClicked );

            /* Handle Security Settings tab selected. */
            $( '#dc-security-settings-btn' ).click( _discordCrypt._onSecurityTabButtonClicked );

            /* Handle Automatic Updates button clicked. */
            $( '#dc-automatic-updates-enabled' ).change( _discordCrypt._onAutomaticUpdateCheckboxChanged );

            /* Handle checking for updates. */
            $( '#dc-update-check-btn' ).click( _discordCrypt._onCheckForUpdatesButtonClicked );

            /* Handle Database Import button. */
            $( '#dc-import-database-btn' ).click( _discordCrypt._onImportDatabaseButtonClicked );

            /* Handle Database Export button. */
            $( '#dc-export-database-btn' ).click( _discordCrypt._onExportDatabaseButtonClicked );

            /* Handle Clear Database Entries button. */
            $( '#dc-erase-entries-btn' ).click( _discordCrypt._onClearDatabaseEntriesButtonClicked );

            /* Handle Settings tab closing. */
            $( '#dc-exit-settings-btn' ).click( _discordCrypt._onSettingsCloseButtonClicked );

            /* Handle Save settings. */
            $( '#dc-settings-save-btn' ).click( _discordCrypt._onSaveSettingsButtonClicked );

            /* Handle Reset settings. */
            $( '#dc-settings-reset-btn' ).click( _discordCrypt._onResetSettingsButtonClicked );

            /* Handle Restart-Now button clicking. */
            $( '#dc-restart-now-btn' ).click( _discordCrypt._onUpdateRestartNowButtonClicked );

            /* Handle Restart-Later button clicking. */
            $( '#dc-restart-later-btn' ).click( _discordCrypt._onUpdateRestartLaterButtonClicked );

            /* Handle Ignore-Update button clicking. */
            $( '#dc-ignore-update-btn' ).click( _discordCrypt._onUpdateIgnoreButtonClicked );

            /* Quickly generate and send a public key. */
            $( '#dc-quick-exchange-btn' ).click( _discordCrypt._onQuickHandshakeButtonClicked );

            /* Show the overlay when clicking the password button. */
            dc_passwd_btn.click( _discordCrypt._onOpenPasswordMenuButtonClicked );

            /* Update the password for the user once clicked. */
            $( '#dc-save-pwd' ).click( _discordCrypt._onSavePasswordsButtonClicked );

            /* Reset the password for the user to the default. */
            $( '#dc-reset-pwd' ).click( _discordCrypt._onResetPasswordsButtonClicked );

            /* Hide the overlay when clicking cancel. */
            $( '#dc-cancel-btn' ).click( _discordCrypt._onClosePasswordMenuButtonClicked );

            /* Copy the current passwords to the clipboard. */
            $( '#dc-cpy-pwds-btn' ).click( _discordCrypt._onCopyCurrentPasswordsButtonClicked );

            /* Set whether auto-encryption is enabled or disabled. */
            dc_lock_btn.click( _discordCrypt._onForceEncryptButtonClicked );
        }

        /**
         * @private
         * @desc Sets up the hooking methods required for plugin functionality.
         */
        static _hookSetup() {
            try {
                /* Get module searcher for caching. */
                const searcher = _discordCrypt._getWebpackModuleSearcher();

                /* Resolve and cache all modules needed. */
                _cachedModules = {
                    NonceGenerator: searcher
                        .findByUniqueProperties( [ "extractTimestamp", "fromTimestamp" ] ),
                    MessageCreator: searcher
                        .findByUniqueProperties( [ "createMessage", "parse", "unparse" ] ),
                    MessageController: searcher
                        .findByUniqueProperties( [ "sendClydeError", "sendBotMessage" ] ),
                    MarkdownParser: searcher
                        .findByUniqueProperties( [ "parseInline", "defaultParseBlock" ] ),
                    GlobalTypes: searcher
                        .findByUniqueProperties( [ "ActionTypes", "ActivityTypes" ] ),
                    EventDispatcher: searcher
                        .findByUniqueProperties( [ "dispatch", "maybeDispatch", "dirtyDispatch" ] ),
                    MessageQueue: searcher
                        .findByUniqueProperties( [ "enqueue", "handleSend", "handleResponse" ] ),
                    UserStore: searcher
                        .findByUniqueProperties( [ "getUser", "getUsers", "findByTag", 'getCurrentUser' ] ),
                    GuildStore: searcher
                        .findByUniqueProperties( [ "getGuild", "getGuilds" ] ),
                    ChannelStore: searcher
                        .findByUniqueProperties( [ "getChannel", "getChannels", "getDMFromUserId", 'getDMUserIds' ] ),
                };

                /* Throw an error if a cached module can't be found. */
                for ( let prop in _cachedModules ) {
                    if ( typeof _cachedModules[ prop ] !== 'object' ) {
                        global.smalltalk.alert(
                            'Error Loading DiscordCrypt',
                            `Could not find requisite module: ${prop}`
                        );
                        return;
                    }
                }

                /* Hook switch events as the main event processor. */
                if ( !_discordCrypt._hookMessageCallbacks() ) {
                    global.smalltalk.alert( 'Error Loading DiscordCrypt', `Failed to hook the required modules.` );
                    return;
                }

                /* Patch emoji selection to force it to be enabled for full-encryption messages. */
                _discordCrypt._monkeyPatch(
                    searcher.findByUniqueProperties( [ 'isEmojiDisabled' ] ),
                    'isEmojiDisabled',
                    {
                        instead: ( patchData ) => {
                            try {
                                if(
                                    _discordCrypt._getChannelId() === patchData.methodArguments[ 1 ].id &&
                                    _discordCrypt._hasCustomPassword( patchData.methodArguments[ 1 ].id ) &&
                                    _discordCrypt._getAutoEncrypt()
                                )
                                    return false;
                            }
                            catch( e ) {
                                /* Ignore. */
                            }

                            return patchData.callOriginalMethod();
                        }
                    }
                )
            }
            catch( e ) {
                _discordCrypt.log( 'Could not hook the required methods. If this is a test, that\'s fine.', 'warn' );
            }
        }

        /**
         * @private
         * @desc Hook Discord's internal event handlers for message decryption.
         * @return {boolean} Returns true if handler events have been hooked.
         */
        static _hookMessageCallbacks() {
            /* Hook the event dispatchers. */
            _discordCrypt._monkeyPatch(
                _cachedModules.EventDispatcher,
                'dispatch',
                { instead: _discordCrypt._onDispatchEvent }
            );
            _discordCrypt._monkeyPatch(
                _cachedModules.EventDispatcher,
                'dirtyDispatch',
                { instead: _discordCrypt._onDispatchEvent }
            );
            _discordCrypt._monkeyPatch(
                _cachedModules.EventDispatcher,
                'maybeDispatch',
                { instead: _discordCrypt._onDispatchEvent }
            );

            /* Hook the outgoing message queue handler to encrypt messages & save the original enqueue. */
            _cachedModules.MessageQueue.original_enqueue = _discordCrypt._monkeyPatch(
                _cachedModules.MessageQueue,
                'enqueue',
                { instead: _discordCrypt._onOutgoingMessage }
            ).original;

            /* Hook CHANNEL_SWITCH for toolbar and menu reloading. */
            _eventHooks.push( { type: 'CHANNEL_SELECT', callback: _discordCrypt._onChannelSwitched } );

            /* Hook MESSAGE_CREATE function for single-load messages. */
            _eventHooks.push( { type: 'MESSAGE_CREATE', callback: _discordCrypt._onIncomingMessage } );

            /* Hook MESSAGE_UPDATE function for single-edited messages. */
            _eventHooks.push( { type: 'MESSAGE_UPDATE', callback: _discordCrypt._onIncomingMessage } );

            /* Hook LOAD_MESSAGES_SUCCESS function for bulk-messages. */
            _eventHooks.push( { type: 'LOAD_MESSAGES_SUCCESS', callback: _discordCrypt._onIncomingMessages } );

            /* Hook LOAD_MESSAGES_AROUND_SUCCESS for location-jumping decryption.  */
            _eventHooks.push( { type: 'LOAD_MESSAGES_AROUND_SUCCESS', callback: _discordCrypt._onIncomingMessages } );

            /* Hook LOAD_RECENT_MENTIONS_SUCCESS which is required to decrypt mentions. */
            _eventHooks.push( { type: 'LOAD_RECENT_MENTIONS_SUCCESS', callback: _discordCrypt._onIncomingMessages } );

            /* Hook LOAD_PINNED_MESSAGES_SUCCESS for searching encrypted messages. */
            _eventHooks.push( { type: 'LOAD_PINNED_MESSAGES_SUCCESS', callback: _discordCrypt._onIncomingMessages } );

            return true;
        }

        /**
         * @private
         * @desc The event handler that fires whenever a new event occurs in Discord.
         * @param {Object} event The event that occurred.
         */
        static _onDispatchEvent( event ) {
            let handled = false;

            try {
                for( let i = 0; i < _eventHooks.length; i++ )
                    if( event.methodArguments[ 0 ].type === _eventHooks[ i ].type ) {
                        _eventHooks[ i ].callback( event );
                        handled = true;
                    }
            }
            catch( e ) {
                /* Ignore. */
            }

            if( !handled )
                event.callOriginalMethod();
        }

        /**
         * @private
         * @desc The event handler that fires when a channel is switched.
         * @param {Object} event The channel switching event object.
         */
        static _onChannelSwitched( event ) {
            let id = event.methodArguments[ 0 ].channelId;

            /* Skip channels not currently selected. */
            if ( _discordCrypt._getChannelId() === id )
                /* Delays are required due to windows being loaded async. */
                setTimeout(
                    () => {
                        _discordCrypt.log( 'Detected chat switch.', 'debug' );

                        /* Checks if channel has any settings. */
                        if( _configFile && !_configFile.channels[ id ] ) {

                            /* Create the defaults. */
                            _configFile.channels[ id ] = {
                                primaryKey: null,
                                secondaryKey: null,
                                autoEncrypt: true,
                                ignoreIds: []
                            };
                        }

                        /* Update the lock icon since it is local to the channel */
                        _discordCrypt._updateLockIcon( _self );

                        /* Add the toolbar. */
                        _discordCrypt._loadToolbar();
                    },
                    1
                );

            /* Call the original method. */
            event.callOriginalMethod();
        }

        /**
         * @private
         * @desc The event handler that fires when an incoming message is received.
         * @param {Object} event The message event object.
         * @return {Promise<void>}
         */
        static _onIncomingMessage( event ) {
            /**
             * @type {Message}
             */
            let message = event.methodArguments[ 0 ].message;
            let id = event.methodArguments[ 0 ].channelId || message.channel_id;

            /* Skip if this has no inline-code blocks. */
            if( !_discordCrypt._isFormattedMessage( message.content ) ) {
                event.callOriginalMethod();
                return;
            }

            /* Pretend no message was received till the configuration is unlocked. */
            ( async () => {
                /* Wait for the configuration file to be loaded. */
                while( !_configFile )
                    await ( new Promise( r => setTimeout( r, 1000 ) ) );

                /* Use the default password for decryption if one hasn't been defined for this channel. */
                let primary_key = Buffer.from(
                    _configFile.channels[ id ] && _configFile.channels[ id ].primaryKey ?
                        _configFile.channels[ id ].primaryKey :
                        _configFile.defaultPassword
                );
                let secondary_key = Buffer.from(
                    _configFile.channels[ id ] && _configFile.channels[ id ].secondaryKey ?
                        _configFile.channels[ id ].secondaryKey :
                        _configFile.defaultPassword
                );

                /* Decrypt the content. */
                let r = _discordCrypt._parseMessage(
                    message,
                    primary_key,
                    secondary_key,
                    _configFile.decryptedPrefix
                );

                /* Assign it to the object if valid. */
                if( typeof r === 'string' ) {
                    /* Make sure the string has an actual length or pretend the message doesn't exist. */
                    if( !r.length )
                        return;

                    /* Calculate any mentions. */
                    let mentioned = _discordCrypt._getMentionsForMessage( r, id );

                    /* Apply. */
                    event.methodArguments[ 0 ].message.content = r;
                    if( mentioned.mentions.length )
                        event.methodArguments[ 0 ].message.mentions = mentioned.mentions;
                    if( mentioned.mention_roles.length )
                        event.methodArguments[ 0 ].message.mention_roles = mentioned.mention_roles;
                    event.methodArguments[ 0 ].message.mention_everyone = mentioned.mention_everyone;

                    event.originalMethod.apply( event.thisObject, event.methodArguments );
                    return;
                }

                /* Call the original method on failure. */
                event.callOriginalMethod();
            } )();
        }

        /**
         * @private
         * @desc The event handler that fires when a channel's messages are to be loaded.
         * @param {Object} event The channel loading event object.
         * @return {Promise<void>}
         */
        static _onIncomingMessages( event ) {
            let id = event.methodArguments[ 0 ].channelId;

            /* Pretend no message was received till the configuration is unlocked. */
            ( async () => {
                /* Wait for the configuration file to be loaded. */
                while ( !_configFile )
                    await ( new Promise( r => setTimeout( r, 1000 ) ) );

                /* Iterate all messages being received. */
                for ( let i = 0; i < event.methodArguments[ 0  ].messages.length; i++ ) {
                    let message = event.methodArguments[ 0 ].messages[ i ];

                    /* Skip if this has no inline-code blocks. */
                    if ( !_discordCrypt._isFormattedMessage( message.content ) )
                        continue;

                    /* Use the default password for decryption if one hasn't been defined for this channel. */
                    let primary_key = Buffer.from(
                        _configFile.channels[ id ] && _configFile.channels[ id ].primaryKey ?
                            _configFile.channels[ id ].primaryKey :
                            _configFile.defaultPassword
                    );
                    let secondary_key = Buffer.from(
                        _configFile.channels[ id ] && _configFile.channels[ id ].secondaryKey ?
                            _configFile.channels[ id ].secondaryKey :
                            _configFile.defaultPassword
                    );

                    /* Decrypt the content. */
                    let r = _discordCrypt._parseMessage(
                        message,
                        primary_key,
                        secondary_key,
                        _configFile.decryptedPrefix
                    );

                    /* Assign it to the object if valid. */
                    if ( typeof r === 'string' ) {
                        /* Make sure the string has an actual length or pretend the message doesn't exist. */
                        if( !r.length ) {
                            delete event.methodArguments[ 0 ].messages[ i ];
                            continue;
                        }

                        /* Calculate any mentions. */
                        let mentioned = _discordCrypt._getMentionsForMessage( r, id );

                        event.methodArguments[ 0 ].messages[ i ].content = r;
                        if ( mentioned.mentions.length )
                            event.methodArguments[ 0 ].messages[ i ].mentions = mentioned.mentions;
                        if ( mentioned.mention_roles.length )
                            event.methodArguments[ 0 ].messages[ i ].mention_roles = mentioned.mention_roles;
                        event.methodArguments[ 0 ].messages[ i ].mention_everyone = mentioned.mention_everyone;
                    }
                }

                /* Filter out any deleted messages. */
                event.methodArguments[ 0 ].messages =
                    event.methodArguments[ 0 ].messages.filter( ( i ) => i );

                /* Call the original method using the modified contents. ( If any. ) */
                event.originalMethod.apply( event.thisObject, event.methodArguments );
            } )();
        }

        /**
         * @private
         * @desc The event handler that fires when an outgoing message is being sent.
         * @param {Object} event The outgoing message event object.
         * @return {Promise<void>}
         */
        static _onOutgoingMessage( event ) {
            ( async () => {
                /* Wait till the configuration file has been loaded before parsing any messages. */
                await ( async () => {
                    while( !_configFile )
                        await ( new Promise( r => setTimeout( r, 1000 ) ) );
                } )();

                let message = event.methodArguments[ 0 ].message;

                let r = _discordCrypt._tryEncryptMessage( message.content, false, message.channelId );

                if( typeof r === 'boolean' ) {
                    event.callOriginalMethod();
                    return;
                }

                event.methodArguments[ 0 ].message.content = r[ 0 ].message;
                event.originalMethod.apply( event.thisObject, event.methodArguments );

                if( r.length === 1 )
                    return;

                for( let i = 1; i < r.length; i++ )
                    _discordCrypt._dispatchMessage( r[ i ].message, message.channelId );
            } )();
        }

        /**
         * @private
         * @desc Updates the auto-encrypt toggle
         * @param {boolean} enable
         */
        static _setAutoEncrypt( enable ) {
            _configFile.channels[ _discordCrypt._getChannelId() ].autoEncrypt = enable;
        }

        /**
         * @private
         * @desc Returns whether or not auto-encrypt is enabled.
         * @param {string} [id] Optional channel ID to retrieve the status for.
         * @returns {boolean}
         */
        static _getAutoEncrypt( id ) {
            id = id || _discordCrypt._getChannelId();

            /* Quick sanity check. */
            if( !_configFile || !_configFile.channels[ id ] )
                return true;

            /* Fetch the current value. */
            return _configFile.channels[ id ].autoEncrypt;
        }

        /**
         * @private
         * @desc Determines if a custom password exists for the specified channel.
         * @param {string} channel_id The target channel's ID.
         * @return {boolean} Returns true if a custom password is set.
         */
        static _hasCustomPassword( channel_id ) {
            return _configFile.channels[ channel_id ] &&
                _configFile.channels[ channel_id ].primaryKey &&
                _configFile.channels[ channel_id ].secondaryKey;
        }

        /**
         * @private
         * @desc Handles a key exchange request that has been accepted.
         * @param {Message} message The input message object.
         * @param {PublicKeyInfo} remoteKeyInfo The public key's information.
         * @return {string} Returns the resulting message string.
         */
        static _handleAcceptedKeyRequest( message, remoteKeyInfo ) {
            let encodedKey;

            /* If a local key doesn't exist, generate one and send it. */
            if(
                !_globalSessionState.hasOwnProperty( message.channel_id ) ||
                !_globalSessionState[ message.channel_id ].privateKey
            ) {
                /* Create the session object. */
                _globalSessionState[ message.channel_id ] = {};

                /* Generate a local key pair. */
                if( remoteKeyInfo.algorithm.toLowerCase() === 'dh' )
                    _globalSessionState[ message.channel_id ].privateKey =
                        _discordCrypt.__generateDH( remoteKeyInfo.bit_length );
                else
                    _globalSessionState[ message.channel_id ].privateKey =
                        _discordCrypt.__generateECDH( remoteKeyInfo.bit_length );

                /* Get the public key for this private key. */
                encodedKey = _discordCrypt.__encodeExchangeKey(
                    Buffer.from(
                        _globalSessionState[ message.channel_id ].privateKey.getPublicKey(
                            'hex',
                            remoteKeyInfo.algorithm.toLowerCase() === 'ecdh' ? 'compressed' : null
                        ),
                        'hex'
                    ),
                    remoteKeyInfo.index
                );

                /* Dispatch the public key. */
                _discordCrypt._dispatchMessage(
                    `\`${encodedKey}\``,
                    message.channel_id,
                    KEY_DELETE_TIMEOUT
                );

                /* Get the local key info. */
                _globalSessionState[ message.channel_id ].localKey = _discordCrypt.__extractExchangeKeyInfo(
                    encodedKey,
                    true
                );
            }

            /* Save the remote key's information. */
            _globalSessionState[ message.channel_id ].remoteKey = remoteKeyInfo;

            /* Try deriving the key. */
            let keys = _discordCrypt._deriveExchangeKeys( message.channel_id );

            /* Remove the entry. */
            delete _globalSessionState[ message.channel_id ];

            /* Validate the keys. */
            if( !keys || !keys.primaryKey || !keys.secondaryKey ) {
                _discordCrypt.log(
                    `Failed to establish a session in channel: ${message.channel_id}`,
                    'error'
                );

                /* Display a message to the user. */
                return '🚫 **[ ERROR ]** FAILED TO ESTABLISH A SESSION !!!';
            }

            /* Apply the keys. */
            _configFile.channels[ message.channel_id ].primaryKey = keys.primaryKey;
            _configFile.channels[ message.channel_id ].secondaryKey = keys.secondaryKey;

            /* Save the configuration to update the keys and timed messages. */
            _discordCrypt._saveConfig();

            /* Set the new message text. */
            return '🔏 **[ SESSION ]** *ESTABLISHED NEW SESSION* !!!\n' +
                `Primary Entropy: **${_discordCrypt.__entropicBitLength( keys.primaryKey )} Bits**\n` +
                `Secondary Entropy: **${_discordCrypt.__entropicBitLength( keys.secondaryKey )} Bits**`;
        }

        /**
         * @private
         * @desc Parses a public key message.
         * @param {Message} message The message object.
         * @param {string} content The message's content.
         * @returns {string} Returns a result string indicating the message info.
         */
        static _parseKeyMessage( message, content ) {
            /* Ignore messages that are older than 6 hours. */
            if( message.timestamp && ( Date.now() - ( new Date( message.timestamp ) ) ) > KEY_IGNORE_TIMEOUT )
                return '';

            /* Extract the algorithm info from the message's metadata. */
            let remoteKeyInfo = _discordCrypt.__extractExchangeKeyInfo( content, true );

            /* Sanity check for invalid key messages. */
            if ( remoteKeyInfo === null )
                return '🚫 **[ ERROR ]** *INVALID PUBLIC KEY* !!!';

            /* Validate functions. */
            if(
                !_cachedModules.UserStore ||
                typeof _cachedModules.UserStore.getCurrentUser !== 'function' ||
                typeof _cachedModules.UserStore.getUser !== 'function' ||
                typeof _cachedModules.ChannelStore.getChannels !== 'function'
            )
                return '🚫 **[ ERROR ]** *CANNOT RESOLVE DEPENDENCY MODULE* !!!';

            /* Make sure that this key wasn't somehow sent in a guild or group DM. */
            // noinspection JSUnresolvedFunction
            let channels = _cachedModules.ChannelStore.getChannels();
            if( channels && channels[ message.channel_id ] && channels[ message.channel_id ].type !== 1 )
                return '🚫 **[ ERROR ]** *INCOMING KEY EXCHANGE FROM A NON-DM* !!!';

            /* Retrieve the current user's information. */
            // noinspection JSUnresolvedFunction
            let currentUser = _cachedModules.UserStore.getCurrentUser(),
                remoteUser = _cachedModules.UserStore.getUser( message.author.id );

            /* Check if the key being received is in the ignore list and just make it invisible. */
            if(
                _configFile.channels[ message.channel_id ] &&
                _configFile.channels[ message.channel_id ].ignoreIds.indexOf( message.id ) !== -1
            )
                return '';

            /* Verify this message isn't coming from us. */
            if( message.author.id === currentUser.id ) {
                /* If it is, ensure we have a private key for it. */
                if(
                    !_globalSessionState.hasOwnProperty( message.channel_id ) ||
                    !_globalSessionState[ message.channel_id ].privateKey
                )
                    return '🔏 **[ SESSION ERROR ]** *OUTGOING KEY EXCHANGE WITH NO PRIVATE KEY* !!!';

                return '🔏 **[ SESSION ]** *OUTGOING KEY EXCHANGE*';
            }

            /* Be sure to add the message ID to the ignore list. */
            _configFile.channels[ message.channel_id ].ignoreIds.push( message.id );
            _discordCrypt._saveConfig();

            /* Check if this is an incoming key exchange or a resulting message. */
            if( _globalSessionState.hasOwnProperty( message.channel_id ) )
                return _discordCrypt._handleAcceptedKeyRequest( message, remoteKeyInfo );

            /* Actually just the return string for the message. */
            let returnValue = '';

            /* The author is attempting to initiate a key exchange. Prompt the user on whether to accept it. */
            ( async function() {
                await global.smalltalk.confirm(
                    '----- INCOMING KEY EXCHANGE REQUEST -----',
                    `User @${remoteUser.username}#${remoteUser.discriminator} wants to perform a key exchange.` +
                    '\n\n' +
                    `Algorithm: ${remoteKeyInfo.algorithm.toUpperCase()}-${remoteKeyInfo.bit_length}` +
                    '\n' +
                    `Checksum: ${remoteKeyInfo.fingerprint}` +
                    '\n\n' +
                    'Do you wish to start a new secure session with them using these parameters?'
                ).then(
                    () => {
                        /* The user accepted the request. Handle the key exchange.  */
                        returnValue = _discordCrypt._handleAcceptedKeyRequest( message, remoteKeyInfo );
                    },
                    () => {
                        /* The user rejected the request. */
                        returnValue = '🔏 **[ INFO ]** *IGNORED EXCHANGE MESSAGE*';
                    }
                )
            } )();

            return returnValue;
        }

        /**
         * @private
         * @desc Detects and returns all roles & users mentioned in a message.
         *      Shamelessly "stolen" from BetterDiscord team. Thanks guys. :D
         * @param {string} message The input message.
         * @param {string} [id] The channel ID this message will be dispatched to.
         * @return {MessageMentions}
         */
        static _getMentionsForMessage( message, id ) {
            /*  */
            const user_mentions = /<@!?([0-9]{10,24})>/g,
                role_mentions = /<@&([0-9]{10,})>/g,
                everyone_mention = /(?:\s+|^)@everyone(?:\s+|$)/;

            /* Actual format as part of a message object. */
            let mentions = {
                mentions: [],
                mention_roles: [],
                mention_everyone: false
            };

            /* Get the channel's ID. */
            id = id || _discordCrypt._getChannelId();

            /* Get the channel's properties. */
            let props = _discordCrypt._getChannelProps( id );

            /* Check if properties were retrieved. */
            if( !props ) {
                return mentions;
            }

            /* Parse the message into ID based format. */
            message = _cachedModules.MessageCreator.parse( props, message ).content;

            /* Check for user tags. */
            if( user_mentions.test( message ) ) {
                /* Retrieve all user IDs in the parsed message. */
                mentions.mentions = message
                    .match( user_mentions )
                    .map( m => {
                        return {id: m.replace( /[^0-9]/g, '' )}
                    } );
            }

            /* Gather role mentions. */
            if( role_mentions.test( message ) ) {
                /* Retrieve all role IDs in the parsed message. */
                mentions.mention_roles = message
                    .match( role_mentions )
                    .map( m => m.replace( /[^0-9]/g, '' ) );
            }

            /* Detect if mentioning everyone. */
            mentions.mention_everyone = everyone_mention.test( message );

            return mentions;
        }

        /**
         * @private
         * @desc Parses a raw message and returns the decrypted result.
         * @param {Message} message The message object.
         * @param {string} primary_key The primary key used to decrypt the message.
         * @param {string} secondary_key The secondary key used to decrypt the message.
         * @param {string} [prefix] Messages that are successfully decrypted should have this prefix prepended.
         * @return {string|boolean} Returns false if a message isn't in the correct format or the decrypted result.
         */
        static _parseMessage( message, primary_key, secondary_key, prefix ) {
            /* Get the message's content. */
            let content = message.content.substr( 1, message.content.length - 2 );

            /* Skip if the message is <= size of the total header. */
            if ( content.length <= 12 )
                return false;

            /* Split off the magic. */
            let magic = content.slice( 0, 4 );

            /* If this is a public key, just add a button and continue. */
            if ( magic === ENCODED_KEY_HEADER )
                return _discordCrypt._parseKeyMessage( message, content );

            /* Make sure it has the correct header. */
            if ( magic !== ENCODED_MESSAGE_HEADER )
                return false;

            /* Try to deserialize the metadata. */
            let metadata = _discordCrypt.__metaDataDecode( content.slice( 4, 8 ) );

            /* Try looking for an algorithm, mode and padding type. */
            /* Algorithm first. */
            if ( metadata[ 0 ] >= ENCRYPT_MODES.length )
                return false;

            /* Cipher mode next. */
            if ( metadata[ 1 ] >= ENCRYPT_BLOCK_MODES.length )
                return false;

            /* Padding after. */
            if ( metadata[ 2 ] >= PADDING_SCHEMES.length )
                return false;

            /* Decrypt the message. */
            let dataMsg = _discordCrypt.__symmetricDecrypt( content.replace( /\r?\n|\r/g, '' )
                .substr( 8 ), primary_key, secondary_key, metadata[ 0 ], metadata[ 1 ], metadata[ 2 ], true );

            /* If successfully decrypted, add the prefix if necessary and return the result. */
            if ( ( typeof dataMsg === 'string' || dataMsg instanceof String ) && dataMsg !== "" ) {
                /* If a prefix is being used, add it now. */
                if( prefix && typeof prefix === 'string' && prefix.length > 0 )
                    dataMsg = prefix + dataMsg;

                /* Return. */
                return dataMsg;
            }

            switch( dataMsg ) {
            case 1:
                return '🚫 [ ERROR ] AUTHENTICATION OF CIPHER TEXT FAILED !!!';
            case 2:
                return '🚫 [ ERROR ] FAILED TO DECRYPT CIPHER TEXT !!!';
            default:
                return '🚫 [ ERROR ] DECRYPTION FAILURE. INVALID KEY OR MALFORMED MESSAGE !!!';
            }
        }

        /**
         * @private
         * @desc Attempts to encrypt a message using the key from the channel ID provided.
         * @param {string} message The input message to encrypt.
         * @param {boolean} ignore_trigger Whether to ignore checking for Config::encodeMessageTrigger and
         *      always encrypt.
         * @param {string} channel_id The channel ID to send this message to.
         * @return {Array<{message: string}>|boolean} Returns one or multiple packets containing the encrypted text.
         *      Returns false on failure.
         */
        static _tryEncryptMessage( message, ignore_trigger, channel_id ) {
            /* Add the message signal handler. */
            const escapeCharacters = [ "/" ];
            const crypto = require( 'crypto' );

            let cleaned, id = channel_id || '0';

            /* Skip messages starting with pre-defined escape characters. */
            if ( message.substr( 0, 2 ) === "##" || escapeCharacters.indexOf( message[ 0 ] ) !== -1 )
                return false;

            /* If we're not encoding all messages or we don't have a password, strip off the magic string. */
            if ( ignore_trigger === false &&
                ( !_configFile.channels[ channel_id ] ||
                    !_configFile.channels[ channel_id ].primaryKey ||
                    !_discordCrypt._getAutoEncrypt() )
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

            /* Get the passwords. */
            let primary_key = Buffer.from(
                _configFile.channels[ id ] && _configFile.channels[ id ].primaryKey ?
                    _configFile.channels[ id ].primaryKey :
                    _configFile.defaultPassword
            );
            let secondary_key = Buffer.from(
                _configFile.channels[ id ] && _configFile.channels[ id ].secondaryKey ?
                    _configFile.channels[ id ].secondaryKey :
                    _configFile.defaultPassword
            );

            /* If the message length is less than the threshold, we can send it without splitting. */
            if ( ( cleaned.length + 16 ) < MAX_ENCODED_DATA ) {
                /* Encrypt the message. */
                let msg = _discordCrypt.__symmetricEncrypt(
                    cleaned,
                    primary_key,
                    secondary_key,
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    true
                );

                /* Append the header to the message normally. */
                msg = ENCODED_MESSAGE_HEADER + _discordCrypt.__metaDataEncode
                (
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    parseInt( crypto.pseudoRandomBytes( 1 )[ 0 ] )
                ) + msg;

                /* Break up the message into lines. */
                msg = msg.replace( /(.{32})/g, ( e ) => `${e}\n` );

                /* Return the message and any user text. */
                return [ {
                    message: `\`${msg}\``
                } ];
            }

            /* Determine how many packets we need to split this into. */
            let packets = _discordCrypt.__splitStringChunks( cleaned, MAX_ENCODED_DATA ), result = [];
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
                msg = ENCODED_MESSAGE_HEADER + _discordCrypt.__metaDataEncode
                (
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    parseInt( crypto.pseudoRandomBytes( 1 )[ 0 ] )
                ) + msg;

                /* Break up the message into lines. */
                msg = msg.replace( /(.{32})/g, ( e ) => `${e}\n` );

                /* Add to the result. */
                result.push( {
                    message: `\`${msg}\``
                } );
            }
            return result;
        }

        /**
         * @private
         * @desc Sends an encrypted message to the current channel.
         * @param {string} message The unencrypted message to send.
         * @param {boolean} [force_send] Whether to ignore checking for the encryption trigger and always encrypt.
         * @param {int} [channel_id] If specified, sends the message to this channel instead of the current channel.
         * @returns {boolean} Returns false if the message failed to be parsed correctly and 0 on success.
         */
        static _sendEncryptedMessage( message, force_send = false, channel_id = undefined ) {
            /* Attempt to encrypt the message. */
            let packets = _discordCrypt._tryEncryptMessage(
                message,
                force_send,
                channel_id || _discordCrypt._getChannelId()
            );

            /* Check if an error occurred. */
            if( typeof packets !== 'object' )
                return false;

            /* Dispatch all messages. */
            for ( let i = 0; i < packets.length; i++ ) {
                /* Send the message. */
                _discordCrypt._dispatchMessage( packets[ i ].message, channel_id );
            }
            /* Save the configuration file and store the new message(s). */
            _discordCrypt._saveConfig();

            return true;
        }

        /**
         * @private
         * @desc Block all forms of tracking.
         */
        static _blockTracking() {
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

                    _Object._freeze( obj.prototype );
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

                    _Object._freeze( obj );
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
         * @param {Object} unlock_btn
         * @param {boolean} cfg_exists
         * @param {Object} pwd_field
         * @param {string} action_msg
         * @param {Object} master_status
         * @return {Function}
         */
        static _onMasterUnlockButtonClicked( unlock_btn, cfg_exists, pwd_field, action_msg, master_status ) {
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
                            if ( !_discordCrypt._loadConfig() ) {
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
                            _self.start();

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
            // noinspection JSUnresolvedFunction
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
         * @returns {Function}
         */
        static _onUploadEncryptedClipboardButtonClicked() {
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
                    _discordCrypt._sendEncryptedMessage( `${file_url}`, true, channel_id );

                    /* Copy the deletion link to the clipboard. */
                    // noinspection JSUnresolvedFunction
                    require( 'electron' ).clipboard.writeText( `Delete URL: ${deletion_link}` );
                }
            );
        }

        /**
         * @private
         * @desc  Uploads the selected file and sends the encrypted link.
         * @returns {Function}
         */
        static _onUploadFileButtonClicked() {
            const fs = require( 'original-fs' );

            let file_path_field = $( '#dc-file-path' );
            let file_upload_btn = $( '#dc-file-upload-btn' );
            let message_textarea = $( '#dc-file-message-textarea' );
            let send_deletion_link = $( '#dc-file-deletion-checkbox' ).is( ':checked' );
            let randomize_file_name = $( '#dc-file-name-random-checkbox' ).is( ':checked' );

            /* Send the additional text first if it's valid. */
            if ( message_textarea.val().length > 0 )
                _discordCrypt._sendEncryptedMessage( message_textarea.val(), true );

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
                    _discordCrypt._sendEncryptedMessage(
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
         * @return {Function}
         */
        static _onDatabaseTabButtonClicked() {
            /* Cache the table. */
            let table = $( '#dc-database-entries' );

            /* Clear all entries. */
            table.html( '' );

            /* Resolve all users, guilds and channels the current user is a part of. */
            // noinspection JSUnresolvedFunction
            let users = _cachedModules.UserStore.getUsers(),
                guilds = _cachedModules.GuildStore.getGuilds(),
                channels = _cachedModules.ChannelStore.getChannels();

            /* Iterate over each password in the configuration. */
            for ( let prop in _configFile.channels ) {
                let name, id = prop;

                /* Skip channels that don't have an ID. */
                if ( !channels[ id ] )
                    continue;

                /* Check for the correct channel type. */
                if ( channels[ id ].type === 0 ) {
                    /* GUILD_TEXT */
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
                else if ( channels[ id ].type === 3 ) {
                    /* GROUP_DM */
                    let max = channels[ id ].recipients.length > 3 ? 3 : channels[ id ].recipients.length,
                        participants = '';

                    /* Iterate the maximum number of users we can display. */
                    for( let i = 0; i < max; i++ ) {
                        let user = users[ channels[ id ].recipients[ i ] ];
                        participants += `@${user.username}#${user.discriminator} `;
                    }

                    /* Indicate this is a DM and give the full user name. */
                    name = `Group DM ${participants}`;
                }
                else
                    continue;

                /* Skip channels that don't have a custom password. */
                if(  !_configFile.channels[ id ].primaryKey || !_configFile.channels[ id ].secondaryKey )
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
                    _configFile.channels[ id ].primaryKey = _configFile.channels[ id ].secondaryKey = null;

                    /* Disable auto-encryption for the channel */
                    _configFile.channels[ id ].autoEncrypt = false;

                    /* Save the configuration. */
                    _discordCrypt._saveConfig();

                    /* Remove the entire row. */
                    delete_btn.parent().parent().remove();
                } );

                /* Handle copy clicks. */
                copy_btn.click( function() {
                    /* Resolve the entry. */
                    let current_keys = _configFile.channels[ id ];
                    let primary = current_keys.primaryKey || _configFile.defaultPassword;
                    let secondary = current_keys.secondaryKey || _configFile.defaultPassword;

                    /* Write to the clipboard. */
                    // noinspection JSUnresolvedFunction
                    require( 'electron' ).clipboard.writeText(
                        `Primary Key: ${primary}\n\nSecondary Key: ${secondary}`
                    );

                    copy_btn.text( 'Copied Keys' );

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
            _discordCrypt._setActiveSettingsTab( 1 );
        }

        /**
         * @private
         * @desc Selects the Security Settings tab and loads all blacklisted updates.
         * @return {Function}
         */
        static _onSecurityTabButtonClicked() {
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
                    _discordCrypt._saveConfig();

                    /* Remove the entire row. */
                    remove_btn.parent().parent().parent().remove();
                } );

                /* Handle the changelog button clicked. */
                changelog_btn.click( function() {
                    global.smalltalk.alert(
                        `Changes`,
                        _discordCrypt.__tryParseChangelog( updateInfo.changelog, _self.getVersion() )
                    );
                } );

                /* Handle the signatures button clicked. */
                info_btn.click( function() {
                    let size = parseFloat( updateInfo.payload.length / 1024.0 ).toFixed( 3 );
                    let key_id = Buffer.from(
                        global
                            .openpgp
                            .key
                            .readArmored( _discordCrypt.__zlibDecompress( PGP_SIGNING_KEY ) )
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
        }

        /**
         * @private
         * @desc Toggles the automatic update checking function.
         * @return {Function}
         */
        static _onAutomaticUpdateCheckboxChanged() {
            /* Set the state. */
            _configFile.automaticUpdates = $( '#dc-automatic-updates-enabled' )
                .is( ':checked' );

            /* Save the configuration. */
            _discordCrypt._saveConfig();

            /* Log. */
            _discordCrypt.log( `${_configFile.automaticUpdates ? 'En' : 'Dis'}abled automatic updates.`, 'debug' );

            /* Skip if we don't need to update. */
            if( !_discordCrypt._shouldIgnoreUpdates( _self.getVersion() ) ) {
                /* If we're doing automatic updates, make sure an interval is set. */
                if( _configFile.automaticUpdates ) {
                    /* Only do this if none is defined. */
                    if( !_updateHandlerInterval ) {
                        /* Add an update handler to check for updates every 60 minutes. */
                        _updateHandlerInterval = setInterval( () => {
                            _self._checkForUpdates();
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

        /**
         * @private
         * @desc Checks for updates immediately.
         * @return {Function}
         */
        static _onCheckForUpdatesButtonClicked() {
            /* Simply call the wrapper, everything else will be handled by this. */
            _self._checkForUpdates();
        }

        /**
         * @private
         * @desc Opens a file dialog to import a JSON encoded entries file.
         * @return {Function}
         */
        static _onImportDatabaseButtonClicked() {
            /* Get the FS module. */
            const fs = require( 'fs' );

            /* Create an input element. */
            // noinspection JSUnresolvedFunction
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
                    if ( !_configFile.channels.hasOwnProperty( e.id ) ) {
                        /* Update the number imported. */
                        imported++;
                    }

                    /* Make sure the entry exists. */
                    if( !_configFile.channels[ e.id ] ) {
                        /* Add it to the configuration file. */
                        _configFile.channels[ e.id ] = {
                            primaryKey: e.primary,
                            secondaryKey: e.secondary,
                            encodeAll: true,
                            ignoreIds: []
                        };
                    }
                    else {
                        /* Update. */
                        _configFile.channels[ e.id ].primaryKey = e.primary;
                        _configFile.channels[ e.id ].secondaryKey = e.secondary;
                    }
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
                _discordCrypt._onDatabaseTabButtonClicked();

                /* Save the configuration. */
                _discordCrypt._saveConfig();
            }
        }

        /**
         * @private
         * @desc Opens a file dialog to import a JSON encoded entries file.
         */
        static _onExportDatabaseButtonClicked() {
            /* Create an input element. */
            // noinspection JSUnresolvedFunction
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
            for ( let prop in _configFile.channels ) {
                let e = _configFile.channels[ prop ];

                /* Skip entries without a primary and secondary key. */
                if( !e || !e.primaryKey || !e.secondaryKey )
                    continue;

                /* Insert the entry to the list. */
                data._discordCrypt_entries.push( {
                    id: prop,
                    primary: e.primaryKey,
                    secondary: e.secondaryKey
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
         * @return {Function}
         */
        static _onClearDatabaseEntriesButtonClicked() {
            /* Cache the button. */
            let erase_entries_btn = $( '#dc-erase-entries-btn' );

            /* Remove all entries. */
            for( let id in _configFile.channels )
                _configFile.channels[ id ].primaryKey = _configFile.channels[ id ].secondaryKey = null;

            /* Clear the table. */
            $( '#dc-database-entries' ).html( '' );

            /* Save the database. */
            _discordCrypt._saveConfig();

            /* Update the button's text. */
            erase_entries_btn.text( 'Cleared Entries' );

            /* Reset the button's text. */
            setTimeout( () => {
                erase_entries_btn.text( 'Erase Entries' );
            }, 1000 );
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
         * @returns {Function}
         */
        static _onSaveSettingsButtonClicked() {
            /* Cache jQuery results. */
            let dc_primary_cipher = $( '#dc-primary-cipher' ),
                dc_secondary_cipher = $( '#dc-secondary-cipher' ),
                dc_master_password = $( '#dc-master-password' ),
                dc_save_settings_btn = $( '#dc-settings-save-btn' );

            /* Update all settings from the settings panel. */
            _configFile.timedMessageExpires = parseInt( $( '#dc-settings-timed-expire' ).val() );
            _configFile.encodeMessageTrigger = $( '#dc-settings-encrypt-trigger' ).val();
            _configFile.decryptedPrefix = $( '#dc-settings-decrypted-prefix' ).val();
            _configFile.encryptBlockMode = $( '#dc-settings-cipher-mode' ).val();
            _configFile.defaultPassword = $( '#dc-settings-default-pwd' ).val();
            _configFile.paddingMode = $( '#dc-settings-padding-mode' ).val();
            _configFile.encryptMode = _discordCrypt
                .__cipherStringToIndex( dc_primary_cipher.val(), dc_secondary_cipher.val() );

            dc_primary_cipher.val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
            dc_secondary_cipher.val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );

            /* Update icon */
            _discordCrypt._updateLockIcon();

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
                            _discordCrypt._saveSettings( dc_save_settings_btn );
                        }

                        return false;
                    }
                );
            }
            else {
                /* Save the configuration file and update the button text. */
                _discordCrypt._saveSettings( dc_save_settings_btn );
            }
        }

        /**
         * @private
         * @desc Resets the user settings to their default values.
         * @returns {Function}
         */
        static _onResetSettingsButtonClicked() {
            /* Resets the configuration file and update the button text. */
            _discordCrypt._resetSettings( $( '#dc-settings-reset-btn' ) );

            /* Update all settings from the settings panel. */
            $( '#dc-secondary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );
            $( '#dc-primary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
            $( '#dc-settings-cipher-mode' ).val( _configFile.encryptBlockMode.toLowerCase() );
            $( '#dc-settings-padding-mode' ).val( _configFile.paddingMode.toLowerCase() );
            $( '#dc-settings-encrypt-trigger' ).val( _configFile.encodeMessageTrigger );
            $( '#dc-settings-timed-expire' ).val( _configFile.timedMessageExpires );
            $( '#dc-settings-decrypted-prefix' ).val( _configFile.decryptedPrefix );
            $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );
            $( '#dc-master-password' ).val( '' );
        }

        /**
         * @private
         * @desc Applies the update & restarts the app by performing changing URLs to /channels/@me.
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

            /* Reload the main URI. */
            window.location.pathname = '/channels/@me';
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
         * @return {Function}
         */
        static _onUpdateIgnoreButtonClicked() {
            /* Clear out the needless data which isn't actually needed to validate a blacklisted update. */
            _updateData.payload = '';

            /* Add the blacklist to the configuration file. */
            _configFile.blacklistedUpdates.push( _updateData );

            /* Save the configuration. */
            _discordCrypt._saveConfig();

            /* Also reset any opened tabs. */
            _discordCrypt._setActiveSettingsTab( 0 );
            _discordCrypt._setActiveExchangeTab( 0 );

            /* Hide the update and changelog. */
            $( '#dc-overlay' ).css( 'display', 'none' );
            $( '#dc-update-overlay' ).css( 'display', 'none' );
        }

        /**
         * @private
         * @desc Generates and sends a new public key.
         */
        static _onQuickHandshakeButtonClicked() {
            const DH_S = _discordCrypt.__getDHBitSizes(),
                ECDH_S = _discordCrypt.__getECDHBitSizes();

            let channelId = _discordCrypt._getChannelId();

            /* Ensure no other keys exist. */
            if( _globalSessionState.hasOwnProperty( channelId ) ) {
                global.smalltalk.alert(
                    '----- WARNING -----',
                    'Cannot start a new session while an existing handshake is pending ...'
                );
                return;
            }

            /* Create the session object. */
            _globalSessionState[ channelId ] = {};
            let isECDH = DH_S.indexOf( _configFile.exchangeBitSize ) === -1;

            /* Generate a local key pair. */
            if( !isECDH )
                _globalSessionState[ channelId ].privateKey =
                    _discordCrypt.__generateDH( _configFile.exchangeBitSize );
            else
                _globalSessionState[ channelId ].privateKey =
                    _discordCrypt.__generateECDH( _configFile.exchangeBitSize );

            /* Get the public key for this private key. */
            let encodedKey = _discordCrypt.__encodeExchangeKey(
                Buffer.from(
                    _globalSessionState[ channelId ].privateKey.getPublicKey( 'hex', isECDH ? 'compressed' : null ),
                    'hex'
                ),
                isECDH ?
                    DH_S.length + ECDH_S.indexOf( _configFile.exchangeBitSize ) :
                    DH_S.indexOf( _configFile.exchangeBitSize )
            );

            /* Dispatch the public key. */
            _discordCrypt._dispatchMessage(
                `\`${encodedKey}\``,
                channelId,
                KEY_DELETE_TIMEOUT
            );

            /* Get the local key info. */
            _globalSessionState[ channelId ].localKey = _discordCrypt.__extractExchangeKeyInfo(
                encodedKey,
                true
            );
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
         * @returns {Function}
         */
        static _onSavePasswordsButtonClicked() {
            let btn = $( '#dc-save-pwd' );

            /* Update the password and save it. */
            _discordCrypt._updatePasswords();

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
        }

        /**
         * @private
         * @desc Resets passwords for the current channel or DM to their defaults.
         * @returns {Function}
         */
        static _onResetPasswordsButtonClicked() {
            let btn = $( '#dc-reset-pwd' );

            /* Disable auto-encrypt for the channel */
            _discordCrypt._setAutoEncrypt( false );

            /* Reset the configuration for this user and save the file. */
            let id = _discordCrypt._getChannelId();
            _configFile.channels[ id ].primaryKey = _configFile.channels[ id ].secondaryKey = null;
            _discordCrypt._saveConfig();

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
            let currentKeys = _configFile.channels[ _discordCrypt._getChannelId() ],
                writeText = require( 'electron' ).clipboard.writeText;

            /* If no password is currently generated, write the default key. */
            if ( !currentKeys || !currentKeys.primaryKey || !currentKeys.secondaryKey ) {
                writeText( `Default Password: ${_configFile.defaultPassword}` );
                return;
            }

            /* Write to the clipboard. */
            writeText( `Primary Key: ${currentKeys.primaryKey}\r\n\r\nSecondary Key: ${currentKeys.secondaryKey}` );

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
         * @returns {Function}
         */
        static _onForceEncryptButtonClicked() {
            /* Cache jQuery results. */
            let dc_lock_btn = $( '#dc-lock-btn' ), new_tooltip = $( '<span>' ).addClass( 'dc-tooltip-text' );

            /* Update the icon and toggle. */
            if ( !_discordCrypt._getAutoEncrypt() ) {
                dc_lock_btn.html( Buffer.from( LOCK_ICON, 'base64' ).toString( 'utf8' ) );
                dc_lock_btn.append( new_tooltip.text( 'Disable Message Encryption' ) );
                _discordCrypt._setAutoEncrypt( true );
            }
            else {
                dc_lock_btn.html( Buffer.from( UNLOCK_ICON, 'base64' ).toString( 'utf8' ) );
                dc_lock_btn.append( new_tooltip.text( 'Enable Message Encryption' ) );
                _discordCrypt._setAutoEncrypt( false );
            }

            /* Save config. */
            _discordCrypt._saveConfig();
        }

        /**
         * @private
         * @desc Updates the lock icon
         */
        static _updateLockIcon() {
            /* Cache jQuery results. */
            let dc_lock_btn = $( '#dc-lock-btn' ), tooltip = $( '<span>' ).addClass( 'dc-tooltip-text' );

            /* Update the icon based on the channel */
            if ( _discordCrypt._getAutoEncrypt() ) {
                dc_lock_btn.html( Buffer.from( LOCK_ICON, 'base64' ).toString( 'utf8' ) );
                dc_lock_btn.append( tooltip.text( 'Disable Message Encryption' ) );
            }
            else {
                dc_lock_btn.html( Buffer.from( UNLOCK_ICON, 'base64' ).toString( 'utf8' ) );
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
         * @desc Derives a primary and secondary key from a session state.
         * @param {string} channelId The channel that this exchange is being computed for.
         * @param {number} outputBitLength The length in bits of the output keys.
         * @return {{primaryKey: string, secondaryKey: string}|null}
         */
        static _deriveExchangeKeys( channelId, outputBitLength = 2048 ) {
            /* Defined customization parameters for the KMAC-256 derivation. */
            const primaryMAC = new Uint8Array( Buffer.from( 'discordCrypt-primary-secret' ) ),
                secondaryMAC = new Uint8Array( Buffer.from( 'discordCrypt-secondary-secret' ) );

            /* Converts a hex-encoded string to a Base64 encoded string. */
            const convert = ( k ) => Buffer.from( k, 'hex' ).toString( 'base64' );

            /* Store the state for easier manipulation. */
            let _state = _globalSessionState[ channelId ];

            /* Calculate the derived secret as a hex encoded string. */
            let derivedKey = _discordCrypt.__computeExchangeSharedSecret( _state.privateKey, _state.remoteKey.key );

            /* Make sure a key was derived. */
            if( !derivedKey )
                return null;

            /* Retrieve the primary and secondary salts. */
            let primarySalt = _discordCrypt.__binaryCompare( _state.localKey.salt, _state.remoteKey.salt ),
                secondarySalt = primarySalt.compare( _state.localKey.salt ) === 0 ?
                    _state.remoteKey.salt :
                    _state.localKey.salt;

            /* Calculate the KMACs for the primary and secondary key. */
            // noinspection JSUnresolvedFunction
            return {
                primaryKey: convert( global.sha3.kmac256( primarySalt, derivedKey, outputBitLength, primaryMAC ) ),
                secondaryKey: convert( global.sha3.kmac256( secondarySalt, derivedKey, outputBitLength, secondaryMAC ) )
            }
        }

        /**
         * @private
         * @desc Determines whether a string is in the correct format of a message.
         * @param {string} message The input message.
         * @return {boolean} Returns true if the string message is valid.
         */
        static _isFormattedMessage( message ) {
            return typeof message === 'string' &&
                message.length > 2 &&
                message[ 0 ] === '`' &&
                message[ message.length - 1 ] === '`';
        }

        /**
         * @private
         * @desc Generates a nonce according to Discord's internal EPOCH. ( 14200704e5 )
         * @return {string} The string representation of the integer nonce.
         */
        static _getNonce() {
            // noinspection JSUnresolvedFunction
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
                                _discordCrypt.__zlibDecompress( PGP_SIGNING_KEY )
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
         * @desc Returns functions to locate exported webpack modules.
         * @returns {WebpackModuleSearcher}
         */
        static _getWebpackModuleSearcher() {
            /* [ Credits to the creator. ] */
            // noinspection JSUnresolvedFunction
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

            for ( let c = getOwnerReactInstance( element ).return; c !== null && c !== undefined; c = c.return ) {
                if ( c !== null && c !== undefined )
                    continue;

                if (
                    c.stateNode !== null && c.stateNode !== undefined &&
                    !( c.stateNode instanceof HTMLElement ) && classFilter( c )
                )
                    return c.stateNode;
            }

            return undefined;
        }

        /**
         * @private
         * @desc Returns the channel properties for the currently viewed channel or null.
         * @param {string} [channel_id] If specified, retrieves the channel properties for this channel.
         *      Else it retrieves the currently viewed channel's properties.
         * @return {object}
         */
        static _getChannelProps( channel_id ) {
            /* Blacklisted IDs that don't have actual properties. */
            const blacklisted_channel_props = [
                '@me',
                'activity'
            ];

            channel_id = channel_id || _discordCrypt._getChannelId();

            /* Skip blacklisted channels. */
            if( channel_id && blacklisted_channel_props.indexOf( channel_id ) === -1 )
                // noinspection JSUnresolvedFunction
                return _cachedModules.ChannelStore.getChannel( channel_id );

            /* Return nothing for invalid channels. */
            return null;
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
            // noinspection JSUnresolvedFunction
            cached_modules.MessageController.deleteMessage( channel_id, message_id );
        }

        /**
         * @private
         * @desc Sends either an embedded message or an inline message to Discord.
         * @param {string} message The main content to send.
         * @param {int} [channel_id] If specified, sends the embedded message to this channel instead of the
         *      current channel.
         * @param {number} [timeout] Optional timeout to delete this message in minutes.
         */
        static _dispatchMessage( message, channel_id = null, timeout = null ) {
            if( !message.length )
                return;

            /* Save the Channel ID. */
            let _channel = channel_id || _discordCrypt._getChannelId();

            /* Handles returns for messages. */
            const onDispatchResponse = ( r ) => {
                /* Check if an error occurred and inform Clyde bot about it. */
                if ( !r.ok ) {
                    /* Perform Clyde dispatch if necessary. */
                    // noinspection JSUnresolvedFunction
                    if (
                        r.status >= 400 &&
                        r.status < 500 &&
                        r.body &&
                        !_cachedModules.MessageController.sendClydeError( _channel, r.body.code )
                    ) {
                        /* Log the error in case we can't manually dispatch the error. */
                        _discordCrypt.log( `Error sending message: ${r.status}`, 'error' );

                        /* Sanity check. */
                        if ( _cachedModules.EventDispatcher === null || _cachedModules.GlobalTypes === null ) {
                            _discordCrypt.log( 'Could not locate the EventDispatcher module!', 'error' );
                            return;
                        }

                        _cachedModules.EventDispatcher.dispatch( {
                            type: _cachedModules.GlobalTypes.ActionTypes.MESSAGE_SEND_FAILED,
                            messageId: r.body.id,
                            channelId: _channel
                        } );
                    }
                }
                else {
                    /* Receive the message normally. */
                    // noinspection JSUnresolvedFunction
                    _cachedModules.MessageController.receiveMessage( _channel, r.body );

                    /* Calculate the timeout. */
                    timeout = timeout || _configFile.timedMessageExpires;

                    /* Add the message to the TimedMessage array. */
                    if ( _configFile.timedMessages && _configFile.timedMessageExpires > 0 ) {
                        _configFile.timedMessages.push( {
                            messageId: r.body.id,
                            channelId: _channel,
                            expireTime: Date.now() + ( timeout * 60000 )
                        } );
                    }
                }
            };

            /* Create the message object and dispatch it to the queue. */
            _cachedModules.MessageQueue.original_enqueue(
                {
                    type: 'send',
                    message: {
                        channelId: _channel,
                        nonce: _discordCrypt._getNonce(),
                        content: message,
                        tts: false
                    }
                },
                onDispatchResponse
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
         * @return {{original: function(), cancel: function()}} Function with no arguments and no return value
         *      that should be called to cancel this patch. You should save and run it when your plugin is stopped.
         *      Also returns the original function.
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
            const { before, after, instead, once = false, silent = false, forcePatch = false } = options;

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
                    let null_fn =  () => {
                        /* Ignore. */
                    };
                    return {
                        original: null_fn,
                        cancel: null_fn
                    }
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

            /* Store the cancel callback. */
            _stopCallbacks.push( cancel );

            /* Return the callback necessary for cancelling and the original function. */
            return {
                original: origMethod,
                cancel: cancel
            };
        }

        /* ========================================================= */

        /* ======================= UTILITIES ======================= */

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

        /**
         * @private
         * @desc Determines which of the two buffers specified contains a larger value.
         * @param {Buffer|Uint8Array} a The first buffer.
         * @param {Buffer|Uint8Array} b The second buffer.
         */
        static __binaryCompare( a, b ) {
            /* Do a simple comparison on the buffers. */
            // noinspection JSUnresolvedFunction
            switch( a.compare( b ) ) {
            /* b > a */
            case 1:
                return b;
            /* a > b */
            case -1:
                return a;
            /* a === b */
            case 0:
            default:
                return a;
            }
        }

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
         * @desc Loads all compiled libraries as needed.
         * @param {LibraryDefinition} libs A list of all libraries to load.
         */
        static __loadLibraries( libs = EXTERNAL_LIBRARIES ) {
            const vm = require( 'vm' );

            /* Inject all compiled libraries based on if they're needed */
            for ( let name in libs ) {
                let libInfo = libs[ name ];

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
         * @private
         * @desc Encodes a public key buffer into the format required.
         * @param {Buffer|Uint8Array} rawKey The raw public key buffer.
         * @param {number} index The algorithm's index related to the public key being encoded.
         * @return {string}
         */
        static __encodeExchangeKey( rawKey, index ) {
            const MAX_SALT_LEN = 32;
            const MIN_SALT_LEN = 16;

            /* Required for generating a random salt. */
            const crypto = require( 'crypto' );

            /* Calculate a random salt length. */
            let saltLen = (
                parseInt( crypto.randomBytes( 1 ).toString( 'hex' ), 16 ) % ( MAX_SALT_LEN - MIN_SALT_LEN )
            ) + MIN_SALT_LEN;

            /* Create a blank payload. */
            let rawBuffer = Buffer.alloc( 2 + saltLen + rawKey.length );

            /* Write the algorithm index. */
            rawBuffer.writeInt8( index, 0 );

            /* Write the salt length. */
            rawBuffer.writeInt8( saltLen, 1 );

            /* Generate a random salt and copy it to the buffer. */
            crypto.randomBytes( saltLen ).copy( rawBuffer, 2 );

            /* Copy the public key to the buffer. */
            rawKey.copy( rawBuffer, 2 + saltLen );

            /* Split the message by adding a new line every 32 characters like a standard PGP message. */
            return (
                ENCODED_KEY_HEADER + _discordCrypt.__substituteMessage( rawBuffer, true )
            ).replace( /(.{32})/g, e => `${e}\n` );
        }

        /**
         * @public
         * @desc Returns the exchange algorithm and bit size for the given metadata as well as a fingerprint.
         * @param {string|Buffer} key_message The encoded metadata to extract the information from.
         * @param {boolean} [header_present] Whether the message's magic string is attached to the input.
         * @returns {PublicKeyInfo|null} Returns the algorithm's bit length and name or null.
         * @example
         * __extractExchangeKeyInfo( public_key, true );
         * @example
         * __extractExchangeKeyInfo( public_key, false );
         */
        static __extractExchangeKeyInfo( key_message, header_present = false ) {
            try {
                let output = [];
                let msg = key_message.replace( /\r?\n|\r/g, '' );

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
                output[ 'index' ] = parseInt( msg[ 0 ] );
                output[ 'bit_length' ] = _discordCrypt.__indexToAlgorithmBitLength( msg[ 0 ] );
                output[ 'algorithm' ] = _discordCrypt.__indexToExchangeAlgorithmString( msg[ 0 ] )
                    .split( '-' )[ 0 ].toLowerCase();

                /* Get the salt length. */
                let salt_len = msg.readInt8( 1 );

                /* Make sure the salt length is valid. */
                if ( salt_len < 16 || salt_len > 32 )
                    return null;

                /* Read the public salt. */
                // noinspection JSUnresolvedFunction
                output[ 'salt' ] = Buffer.from( msg.subarray( 2, 2 + salt_len ) );

                /* Read the key. */
                // noinspection JSUnresolvedFunction
                output[ 'key' ] = Buffer.from( msg.subarray( 2 + salt_len ) );

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
            // noinspection JSUnresolvedFunction
            if ( clipboard.availableFormats().length === 0 )
                return { mime_type: '', name: '', data: null };

            /* Get all available formats. */
            // noinspection JSUnresolvedFunction
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
                        // noinspection JSUnresolvedFunction
                        data = clipboard.readImage().toPNG();
                        break;
                    case 'bmp':
                    case 'bitmap':
                        // noinspection JSUnresolvedFunction
                        data = clipboard.readImage().toBitmap();
                        break;
                    case 'jpg':
                    case 'jpeg':
                        // noinspection JSUnresolvedFunction
                        data = clipboard.readImage().toJPEG( 100 );
                        break;
                    default:
                        break;
                    }
                    break;
                case 'text':
                    /* Resolve what's in the clipboard. */
                    // noinspection JSUnresolvedFunction
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
                    // noinspection JSUnresolvedFunction
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
                // noinspection JSUnresolvedFunction
                cipher_mode_index = [ 'cbc', 'cfb', 'ofb' ].indexOf( cipher_mode_index.toLowerCase() );

            /* Parse the next 8 bits. */
            if ( typeof padding_scheme_index === 'string' )
                // noinspection JSUnresolvedFunction
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
            // noinspection JSUnresolvedFunction
            let tag = global.sha3.kmac256(
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
                // noinspection JSUnresolvedFunction
                let tag = Buffer.from( message.subarray( 0, 32 ) );

                /* Strip off the authentication tag. */
                // noinspection JSUnresolvedFunction
                message = Buffer.from( message.subarray( 32 ) );

                /* Compute the HMAC-SHA3-256 of the cipher text as hex. */
                // noinspection JSUnresolvedFunction
                let computed_tag = Buffer.from(
                    global.sha3.kmac256(
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
    _Object._freeze( _discordCrypt.prototype );

    /* Freeze the class definition. */
    _Object._freeze( _discordCrypt );

    return _discordCrypt;
} )();

/* Also freeze the method. */
Object.freeze( discordCrypt );

/* Required for code coverage reports. */
module.exports = { discordCrypt };
