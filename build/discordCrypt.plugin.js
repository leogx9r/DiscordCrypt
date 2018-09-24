//META{"name":"discordCrypt"}*//

/*@cc_on
@if (@_jscript)
    var shell = WScript.CreateObject("WScript.Shell");
    var fs = new ActiveXObject("Scripting.FileSystemObject");
    var pathPlugins = shell.ExpandEnvironmentStrings("%APPDATA%\BetterDiscord\plugins");
    var pathSelf = WScript.ScriptFullName;
    shell.Popup("It looks like you mistakenly tried to run me directly. (don't do that!)", 0, "I'm a plugin for BetterDiscord", 0x30);
    if (fs.GetParentFolderName(pathSelf) === fs.GetAbsolutePathName(pathPlugins)) {
        shell.Popup("I'm in the correct folder already.\nJust reload Discord with Ctrl+R.", 0, "I'm already installed", 0x40);
    } else if (!fs.FolderExists(pathPlugins)) {
        shell.Popup("I can't find the BetterDiscord plugins folder.\nAre you sure it's even installed?", 0, "Can't install myself", 0x10);
    } else if (shell.Popup("Should I copy myself to BetterDiscord's plugins folder for you?", 0, "Do you need some help?", 0x34) === 6) {
        fs.CopyFile(pathSelf, fs.BuildPath(pathPlugins, fs.GetFileName(pathSelf)), true);
        // Show the user where to put plugins in the future
        shell.Exec("explorer " + pathPlugins);
        shell.Popup("I'm installed!\nJust reload Discord with Ctrl+R.", 0, "Successfully installed", 0x40);
    }
    WScript.Quit();
@else @*/

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
 * @property {boolean} autoAcceptKeyExchanges Whether to automatically accept incoming key exchange requests.
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
 * @typedef {Object} EmbedFooter
 * @property {string} [text] Footer text.
 * @property {string} [icon_url] URL of the footer icon.
 * @property {string} [proxy_icon_url] Alternative URL of the footer icon.
 */

/**
 * @typedef {Object} EmbedImage
 * @property {string} [url] Source url of the image. ( HTTPS links. )
 * @property {string} [proxy_url] Alternative URL to the image.
 * @property {number} [height] The height of the image to scale to.
 * @property {number} [width] The width of the image to scale to.
 */

/**
 * @typedef {Object} EmbedThumbnail
 * @property {string} [url] Source URL of the thumbnail. ( HTTPS links. )
 * @property {string} [proxy_url] Alternative URL to the thumbnail.
 * @property {number} [height] The height of the thumbnail to scale to.
 * @property {number} [width] The width of the thumbnail to scale to.
 */

/**
 * @typedef {Object} EmbedVideo
 * @property {string} [url] Source URL of the video. ( HTTPS links. )
 * @property {number} [height] The height of the video to scale to.
 * @property {number} [width] The width of the video to scale to.
 */

/**
 * @typedef {Object} EmbedProvider
 * @property {string} [name] The name of the provider.
 * @property {string} [url] The URL of the provider.
 */

/**
 * @typedef {Object} EmbedAuthor
 * @property {string} [name] The name of the author.
 * @property {string} [url] Source URL of the author.
 * @property {string} [icon_url] URL of the author's profile icon.
 * @property {string} [proxy_icon_url] Alternative URL of the author's profile icon.
 */

/**
 * @typedef {Object} EmbedField
 * @property {string} [name] The name of the field.
 * @property {string} [value] The value of the field.
 * @property {boolean} [inline] Whether this field should be inlined.
 */

/**
 * @typedef {Object} Embed
 * @desc Details an embedded object that may contain markdown or links.
 * @property {string} [title] Optional title to be used for the embed.
 * @property {string} [type] Type of the embed. Always "rich" for webhook embeds.
 * @property {string} [description] Description of the embed.
 * @property {string} [url] The URL this embed is referencing.
 * @property {string} [timestamp] The timestamp of this embed.
 * @property {number} [color] Color code of the embed.
 * @property {EmbedFooter} [footer] The footer of the embed.
 * @property {EmbedImage} [image] Image information.
 * @property {EmbedThumbnail} [thumbnail] Thumbnail information.
 * @property {EmbedVideo} [video] Video information.
 * @property {EmbedProvider} [provider] Provider information
 * @property {EmbedAuthor} [author] Author information
 * @property {EmbedField[]} [fields] Field information.
 */

/**
 * @typedef {Object} Attachment
 * @property {string} id Attachment snowflake.
 * @property {string} filename Attachment file name.
 * @property {number} size Size of the file in bytes.
 * @property {string} url Link to the attachment.
 * @property {string} proxy_url A proxy to the file's URL.
 * @property {number} [width] Width of the file if it's an image.
 * @property {number} [height] Height of the file if it's an image.
 */

/**
 * @typedef {Object} Message
 * @desc An incoming or outgoing Discord message.
 * @property {Array<Attachment>} [attachments] Message attachments, if any.
 * @property {MessageAuthor} [author] The creator of the message.
 * @property {string} channel_id The channel this message belongs to.
 * @property {string} [content] The raw message content.
 * @property {string} [edited_timestamp] If specified, when this message was edited.
 * @property {string} [guild_id] If this message belongs to a Guild, this is the ID for it.
 * @property {string} id The message's unique ID.
 * @property {Embed} [embed] Optional embed for the outgoing message.
 * @property {Embed[]} [embeds] Optional embeds for the incoming message.
 * @property {MemberInfo} member The statistics for the author.
 * @property {boolean} [mention_everyone] Whether this message attempts to mention everyone.
 * @property {string[]} [mentions] User IDs or roles mentioned in this message.
 * @property {string[]} [mention_roles] Role IDs mentioned in the message.
 * @property {string} nonce The unique timestamp/snowflake for this message.
 * @property {boolean} [pinned] Whether this message was pinned.
 * @property {string} timestamp When this message was sent.
 * @property {boolean} [tts] If this message should use TTS.
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
     * @desc The index of the handler used for garbage collection.
     * @type {int}
     */
    let _garbageCollectorInterval;

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
     * @desc The Nothing-Up-My-Sleeve magic for KMAC key derivation.
     * @type {Buffer}
     */
    const ENCRYPT_PARAMETER = Buffer.from( 'DiscordCrypt KEY GENERATION PARAMETER' );

    /**
     * @private
     * @desc How long after a key-exchange message has been sent should it be ignored in milliseconds.
     * @type {number}
     */
    const KEY_IGNORE_TIMEOUT = 60 * 1000;

    /**
     * @private
     * @desc How long after a key exchange message is sent should a client attempt to delete it in minutes.
     * @type {number}
     */
    const KEY_DELETE_TIMEOUT = 5;

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
     * @desc The default host used to upload encrypted files using the Up1 specification.
     * @type {string}
     */
    const UP1_FILE_HOST = 'https://share.riseup.net';

    /**
     * @private
     * @desc The API key used to authenticate against the Up1 host.
     * @type {string}
     */
    const UP1_FILE_HOST_API_KEY = '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs';

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
        `eNq1Wtlu3EiW/RVCDcwTSce+VNsGpnMWAy03GvCMHupNTmU7hcqSZCmdXr5+zrk3gpny1vagSwsZvLHcfQkGn15dH4brq2dnV+tpf3u7e315f/Z8ePr63X5/ezPsP95tnp3pw1kftt5d372+vby/mt7d7W4vr6bXe3Q+7D/uOPZy/dub+9t3N1fT+nZ3e//LsL+/vHm4u7zf3Oz/fDasd5cPDwu2/fUdsA1P0X/zZde033zYs3/4X0E0/OfN+v7j3X5zNaw6Deh8+vr+yXO58OEdms//Nv9lfvrk9fOnT949H/5ne/0wrG/vrjcPw+Vwtdlt9tfgbXd989uwvx0+3r67Hxaehst/7Df379F6mLHaE1ImFB7eDB+enZm7D2fDx3Z/f3213z478+Zs2G6u32z32j5cb97/5ZaDBzPYgr9TtrGQsPT07nK/Hf5xvds9O9tx8pv7zcezASJ+af0QtpM/TLhac7Bhmw5ui9ZUd5Of/KeXfrDbcLDbKRwm++mljVjQxu1U8Gi28eC3/pA/caF8mNzODW47uU9nlBBYOryBhp+oVv+JrkHf5o/W71Gr/wVsXdcvNzfvHov/sQy79F04Sp/tx9LP1cnl7AtJH3VAkedUBl8oTVe2vBzYwP+n33EZCPhKF58o+a/3fmdiNmbypbzFCPwFLpLT3pmhYJCN7q0ZgpnQlcp+ShyEBXwIb6cAtgBB3x7/aGH5ZMxbwx4B7KV3W2p6C9AwcNHBmX1OQASaQwiTC+Hgc9ri/y0sZnJ1cm4KFuZlPf8BdfwLFh2ffodoYF/Ci3GwymCTkDJ8QQx6jrxOR/ajdQcbfSL/BlQkl6fs7M6aPPhQ34LEPJQhOtLr0TWLTfs8x/1ki8djDHPU5iRNjplkBLh3cSgTZjs7JXiHg3xrUtydmlzfOi7vq6y8dx6YqcRgh5Di2+jRWQ0XrXsuO4U49XuDy33AnfAhxKHfG/yT2tUTGtZPO9vDZr+/vnnz8Ec73H9cP6xv769W9LrhVUP6XV/b3Fy+ZiBYaHl2drN5P9DFvMMf3G5z/4Co+uzMzvYzJ2wjFoeV2Lm4rDx9+H33C9Cvwe/d/eZhc3/YCBvin00QdOBf/nTl+Qu+B/FbV0ZrXtgi8fHCmk/DSxsIQnQ0C8i70bwwB9pCnKMtazsnDHNzsHbESmH2yY5+rrWOeQ7FjWEd5prtZGZj3FjQU6YwG1dHmABmrA26fHIcAEs2c7aF7VQny+s5UDp3IfSYEcS5g3sBchwACc98TPLk2pPj04BnP7o6l+KJZfJzMUpFndJccgLElMB2iXL1a+2VkePSm9N4HBPXfs7gTUYSngPZlsEyzOtgwFZEjm6XZEa/NWCnjXRXERddKc8+lDWojCIJkyADFzyu3gVcMQ7X4i8sQwce18KRH43cs97tyHjy8BmIurXQWVpPVJcbRXVTGEVnuFNfkAHgJgZwaEEtNICpcwS9ZBOyTVuXSceFEkubMCOpuXDbcBFaavwRc0PLIU8Ah0H+BTXJCzvJ4+osLcIiXhgQKxBpJ5N2cIySJ7nucEOglGvkg01x5DWJ0jFLlnFcIEQnAFpBqhSwq+HCIqQioAK70/Gi3EQbDCFRDJHtFB0JxgDBiUgnV8VPlMRPCLGHhtxCyphhBJdhO0CNXINCTdE3fxPkwJo9hyvWLMNzbVhr5IxaTnn0O6L1glylUlQq4lbQH5ew1P3sq2i0EJJMFDTxwpUX1ADxx7XwLvIvxCzSBu+KP0UrdAOLE9PBVbAHVQDJosp4bditzDBJJMB2cMJeFmnaF46241y3fRfmoPZclAzD1UIV4WdKOxq5ipd6HUduchs3LiNMI0EH0D10gAzmMB26EpQZvoiRZbk1oBKmVIlR/1wG2t2uf/tXZZ/PllwGfCstPflhKu8w//0fvu1YbS9vbja74e/EhnT5Y5nyn+fBb6fBY0n6rRjUwpBF5DYFiQwKH84t7UKfWCZ9+RyW0Ul62xPNtw7nRUfnyn6OT3PyHsE0x9GV2ecYEkhfRWQCiwjEPFDhMKkgOEjyDK4ariFwZ2KxqOnmWE2lJ3KNgoITwe3cz8klk633BAebkwEHKzfnUh3WRTFVTM6GKdYRn0muJNLlbA4xWqx7JC4uxJ1bUmdCQMCBcJwtiAeSztAB6goTgnWziyHWmlHLdiFYhiTjUiynQCMT21OaUXobk2LCVg5h0kVEIUksg3N9kAcXkUkyWkRTL7L9ygJHIHGcPMGNE0jzYThZBnI8YpBMizmIEKhQorPstnXO0VdUxaNFqrY5W9lxHqWRTqRx/vWOc7Q7HVUGdXuxItn+FPD02PL8qS25z7p/lUDZFw4DIxfUmCLyiCQbd0QL1cBawMgpkBJanjIpL8mUOpyskx4LKEFvlRWLh0GNoq8vpx+BoufyFSKG4WQZ0PqIj/NHT79qWPoNW8qf316/2dxs7i/3Gw1pCDLfCGqPwtn/K5r9d8M0/Dvi2Prd/Ubi2t32/vJh892A9o2XHt/ddsNSCDuNYsOfLit//6xR7g2vJ/vvASZoY8IuDuFgQMRKxceKZVDVFTZgWQH2miOrVgScBD2iEzHIW9bvSILWcyrCW8bIOiA6VMMVqU3TJyG4JQNMA1wvJK5X+oQVmtFHdsLNDZQvnVzFEyLkIUIpQWVWclYAOcSPRJ9nW6AZxavNlvg8SfRDBkEp14TN+ArQWkgxYBwGGCZEkwt5SQ2RDUL+CXNY3YNqRkeALcIg2ihoyUkBpMkKEAjPC0S55lTaskmE2RohtMz4y06mh0wEgNRkapDlZU4NkbRjZ5RCCWQ66oKYUyohdSaqTDJzknXPKe2ktPtO8AoDo+J1oFc4xU/ps7FJcCIbludZImWn6lxgHLSASJpRTQHmLTAx+AmJDhL1FG2CwcSGh5G/zUR0VXG5mSBMjUxghPiZusiEOMWIbZNqg/NMZ90nQRCOSmzKxg8n52YYsYsaRkeb81xYTYWJTkwX+1GhH5ItojNOU1MrsJeoJqGElk6NZl3VTZkVGRKuGlDtjtRmQfBiw5QM1eIBqVmogLv0WZbFc6Ub2O4Y9BtkR2dpEpbtqiNWKK1pKJ7vt1Det2nN6OCpHqbBFktTksDslmWZFdXvxN3g5N6LDYmCaqC9i+urgzLTp6wDq5docH4UPjNNIjvCehHOSE2J4hSIFlZWIYHqyrLhdWot1nXjx2w+OdELyQAzRfiyjQyJMyokojIqTEojyxzfey35FV8XVM1rWY2pBflmGIAsHttcgVFLtRa79KEQ1d9KIpkKFI6VhOw4izf7FtxiFrxp4Q/aLM3xEIGKytF0J0vd+kiKKgb+U8ShyEVHG1QYxBH6glCG0pe6FUWpN9T7ToweGbRoAMZCQuDgTJsMmlRPbjFAFmuMi2oGgDedI3FbMTVmXXURVI4SDjhGbL92ZQHU5ALkUVzOyX7vKCoUlOIMKKM09JxjbBN57X7PVKCWW7t9I1S5DqpqO0tysItHCRcgOUgcBZIWpnKL6oRorMjdgSmnnkcUO2sPsZ5jGgHoyEWmwB/lEp0GJOrgWCnptNTtKi8eG7qwyGRfPvQZpbuVKl1zYMtRNAK1eYq8T2V1q5aODbvKnGWyBmFYU06dg+R7kob7aUKh65ueqC0DsHAFpXXRelUy1dhxS4wQDQBaJEexeG9OADvpBKUTodE0KGXLxCrexCWbt+ceJGgWTc15SRSmz1hp7SiZhBoRqZeWgSiwssSsrGTjnrtJsR1JaLNsPLfKA0y2UZbFf2kBJjpAGfWoMw3DctpwIgnkiqpWtOhGtkLdRYOaJZG26J6709A2aHBFrUlDUzwxZLqDWi2patEM2URGKPLmbLR/jSyEacYX99eoBVhWRHx5KPI5J7TVeIqqqqako6EgVAPHSvWrwqo9AiGukAP1s6aV0OS+uJCYyzGh1UVMvkcIsN+Tz1KvAOa0nJGSsntYWvhEIGk0qPZrl5CcLXTV0U9a6petkdCIkulxDqptDQm9LafVXrEA2LisswT2VnTgp/Z6QDJAq2GXqEt3XAJ/iwKWryg1DMCo/dLrNeIzbWjNJFOEf42a2YgesGGS9weaAo0Kp9uY9PUos8Q5shnb5B4N1XDV40hI7nWaXYpSSXWawUuvPiVxtkR8VDCgSZ2DkaQVAovKAOsuiSxfux2sJBc1upYSgWFnobo5kZMBS+XjjuwDqsLiUs27EME0v2hgaxUmSyL1asHbk7TvyYhe1RKyXzytLJEodPWdc6Q9uqqy2NmxUcyEzsppJ8zEXtgDlqqaeuwRdsWI2aoAoGqE8E1i7GSqcLptL8WQO92KNaYwL7VsAcvQQMfMrf5gl6wrkgzNAJyWHm7RuRh3afVk7SEFvhu7peZZ924ththlt1dmFY+bWxG9sEkidaHSI5+WuH1iD4e26610wZ9ORv7Q5MNqU3WVlmpTzim76bSNbG4Fe9L92jE+L1sxvovR+B80MDcv5ImU6A2gqJSERZRLEQdQ7mWnzOYbIdnp2dITje+V2ElqjG3j1PZq55K2W7GQNKuIn7XtQ+wkaBhtqcv3WpY5VC3T8b19C53cD7dtmWlBPfVtDX1Ug+1x7//r8BJyhQoaM3bZlVj9O32WVwXinnGpwHu3l2Wa2nu3V/jJs+RTDvKnk08WbNT8OpzpG4t+sovWm59+3fP23fX6t2nzYb29vHnzh39Xsbzy+bfh1ebmavjb5v3w93evd9fr4a+bj9996YOfz9/7PHrBEwv+/iWvsh2KopTlnNHLEZ8rEwO1nbj3ThP92rU2dhmurs2UGGJG9BQ/8ViHXyo8oCGQUSBylDIincvhks9uhMGnKgvFkQvJmZTPPKUMMa4ZotiupurRqPU88YVBjNqGJWcH5HSDwJ6S+OWE/D3gf+wgvlUU7LIB55GXDSQNeLkST5hdDuenjOvx448JLDI6lNFzgxJ58IRwKkeDEXLjWRpCbOUxcfA8C4s8X+Q7cNDnXB5WHpGz2jGQYS4zBhaaji1GKaxXLdiEDiCNXMPEIGTlWrW9nVDB5EzcKMMni7HYlE8USoIMwwubDqSrVnkBn0Zv+FJnZDCMPDwYLc+RX9Q1z/B4aDvxrAtDcPcHm1dpjDxtiyPf/ODBjRWXbVi38aIhqi9AppOceREj4t6OG/cABTtjhzU549EmoiNtoWYeoUUow2Q5TYtcMMgnAGosSc5PIR3s4Mi/x4KFp5oT34QYu4pQHmxsCGEuCWqF+BDyS5YWU4QnIV4McEUY68QyYlpwefQIphH8nKpQv1gIdSVX9HseBkQ9uI2GsopmO1n5Gswdwgs5bWQ/LE/IzXIXGVgeoq6wtMQyiCEEPkB83kJ8bd5o5agUehjtRaigAEQp9TBbapU8UEKu8OC3goaBVVY596iALSTItwDiZKJ8yjUET2dl0+c0ccMrZ7H5HBYQUJN4f+Gj6JCnq/z4IslRvQ/y1QLoRKFbz1FUeOjY1628RmQtsPKsFgkbfaIQC70yUbgohldeiDcVK+i4ADPi9YWr2yke3Dbi1+2QjKKLsNJi8pplIf2mHazAJeX7jUpzkXNu57Dfi8jV8I0g72JGSonfNJTWqs5dqNh+xoF59sWoFg58LZhXePZerH3wQRwFoief8YUvW37nNzn50I/fibCJKwwky3k5JOfk9BxWxQ9UMhxlorE58WFfi3yP4umbodJVLD8JsXRf7DbiJC6CXlg144fnxyOJcRVWUNonKDbKMT7CHl9h05Vs9BjnkkVY9basHCuM0eknF/wyhEzy7TMGyzcYyrF8dgEVFZ4+Fdojv0WDAfFbHG8r6UgQN7BktLMTHy7GiT1CJFBala8DGFEZv/ihSX0VxFlYRRnMRvwvGn5FNqiAR3lDy9Uz5ATfjudeTtBrDBfeb4/RChZEx6BOoAQn7iitw8T6cMeYV6p8cRFXni/8nBy6B2E7GhGCgUOc8vnIOsQEEiatnX5nMAYNtLiHhxZz5fdhEmOs8rXLK89PeOLoxPKdfiuElk1rRiZPjxoZ+sHX6B6m1pzkwekj7u4VbKzws4M0yuwfsFw5n/HciA2/DwjRyP+XA8TC7ytHM4CFR88TAF89Cnv65Or68Pz/AHTVAXo=`;

    /**
     * @desc Contains the raw HTML injected into the overlay to prompt for the master password for database unlocking.
     * @type {string}
     */
    const UNLOCK_HTML =
        `eNptkEFuwyAQRa+CqLJEps7OcbzqAXoFDNhGxYBgnNS3D8RgJ1VZDOjP/OHpt0LdkBJXLDiZWQDpib1Jr9mKEdcshGenSB1qX+azSrg00TcoqcU/pvd2gFXLKwbrGnSmp7gRtVNdZG619c3HMNB4Lrh8NEkmIljmm8OIu7aa6uTtfdU9S3wHx0yxOG9nB38saWCfVsYtgGB18V8Xme/Wv+EXjWTyvFj05JgGBQn7iwHrWZDou3Sqwoa2xI61ftERiGk1mj0Nx4RQZiQplZq630uKJfoXAGtevJuw2+5KwNR8Uno6olqMtvyHiExEejAbTBUxunxt9QFqPKki`;

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
            'curve25519.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'openpgp.js': {"requiresNode":true,"requiresBrowser":true,"minify":false,"code":"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"},
            'scrypt.js': {"requiresNode":true,"requiresBrowser":false,"minify":false,"code":"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"},
            'sha3.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"eNrdWmtT27rW/iuQ6dE4L9oZ33IjWXSgV2gLbek9E7NDohBDsFNbKaUk/u3v0pKVOCF0733OzPlwPlRYj5bWktbdTreH06gvwziyynelaSq2UpmEfVlqjYXcklAKo8lUboXpVhj96I3DwZa8nYgSF1CKzy8FEgIoJB5u3YTRIL7hCYjH+nH3bt5KKkenZ6cv972z45Ozz4fHT08+M2YJ2HbKJCGCbcHYPV6pGA952Npe2X588vTZ2dHpBvJJEvdFmjKWP1R+iCTFO21AKlE8EI8TuBjH573xboSnSUCJ0+eJYVXm/vv3+1/PDj4+f/7sPQqeRgMxDCMxKG0b2ftJ0rs9mA6HIuEplGzH9fxqrd5o9s77SFyqpJNxKK1Sqcyn0PEcXm96Ne7anlNzarzq2jbOm7UuH0LH547t+tytuY7v81rdsRuNmt/lPeg43K3WeK1axc1OrV6vuw7uGUEHpwrzmh4iuN+u1TxX8etDx+YNJOYushgrFjb33EazQX+bNi44ft1veDW/QY9Vp+Y7K6giqyP5AmrmEySt+tVVUjxUEXA8JcjBsy22+G61wKzaKDCrVom4uS79ngxnHbBXhLqN9fXGqsj7d753kUbznmrWL+8rMy1IunwCHVdBaCOv4fOq43b5AFWujlNFY9xCpzQSP0u8dE6ugg+9peOYGf4dhBcilaUuP4c73L3r1IjDLupx/lA8kAtWwpT+zmbWyhwWAS7Ld4mQ0yQqdXQAad/tYhzBCQEVjBYZK8euyPgUE0F0Uen3xmPcOi/z7Xg2ezg6zg5Pzz4dPvucH0dfDA/xKRQ35kwr4KaDrQe2ZExWtMaWT5U+xrFMpn0ZJ3j0Aue5DuL9AmsueGLYby3gaAFF4mbrkshkuTKdDHpS4Gon6Vrl+Zxf/DUnHm7gFW7gdfCXvARHbjxeLFx3/uyno96VeHQn5392DUtDZhjf/DuMr657/d+zvVpjy1FpwzixlIZDsFth+7YyFtGFHLV2dlAJOn3edsJuS3biLggLtyC/eS5UzvnZCku9JYF94k/hUW7lxGjkROCpoFCeNlhszpP8+Bu8acHEWlhD7bjCc+1zJX/OT/kT/pP/gs5d1LsWu6Ur0e/3rkp80hsM0Pl3e/w8lOnuhGtGb4QcxYPdsznP6dE63pJ69NfUV2JJPtXkg1XyTRq6+FsaSjaoKNmsIsV6XUninpYutJYW5++vXWD4ty9w3pFdHsHBhntE9+6x6qvhbBY/Xl4oKlfOb6XAI1gdJOviDXevO7lqd2TX3CbCO0SbLo6OXIjYxeUJXlVAxA/WFKCC5j+4/s2/cX1182OTUxY3L716s/+kpK+/RKMu2fsfXFuuXFvk177Jr93l13A35yfQ6bZM5EuMfNn+tYx8qS8p4Je6JHZ/FaWVNfrkHn0Efz66ExWl1/nZo7sEN8//bIVD66QymaYjtB+/xgshu6J2LUXHRSU3QZnrCNwG0Kw07zCf7SjqVs4wVAzDLiiu8/nc6GYRJ3dyFKaV83Hcv0rxwpymy6dcIgg9jacS++IDvCkkGklEKiRs23qGTSJ2y7/EADtdvuQM+XIqe4k0E1p5Ek8jCU7Ntv+wZLvtlPf2qvkymlevrlG32+7KYfTRk8VG8VMmvQPcnYLlOSxBlt6aXao2WUSfCZUF9lIxx0Yxl3kPgEQ8zymXhU5h3dnQCGjGVS2UteNRdcaqYMq7UAYvpdRoKCNGtNV0AQTIURLfbElFGE3HY6z3oojFjImH+4GyABU/H8NINgjGw7XEGN9ycOv2ap+ES5hpNnUvuFJeyEzQxHPtZAWHwc5/1VbY64vc57GxXzMc9vM2tu5a63zMJ2SVVq89bS11R/5UVgtF93J42LG7BYbY2DutcXu446Alx+WwM+6q2jzEakCmhqW/KQGMjdspUvYU5d6e252B6PS67Xa/47Hxzk5Xq+f3W62JCstRL3mC71L70uqVy23sVR8vWE6W/HYnbdf2G4+txaLlNN3ZZG+vVl5S8cKq25jVPDYprJaRSbWKLzUz3AfVuuf7RX7YeCt+jvswQyWO1bx/IBHvSC9bO5aF72R61bFn9LxyeaWQcoGb69t0msZvT+O4vz3OPz5vy7jNuJdKFfOH+Kb6E8Z8vAep7tsKiWf8R1pMSmFnqF4QbeVH5EUj9KIAlC+1jqxReTXBzclDitwWHR5ic17MDSLqo5Y2dn1utcokpgL0aMCWk0JAo5bc24MGVsg9u1UOK9MoHYVDiQ7NV9b5zk5kqqh4HJqysbvcEeUnz8sbVoAwj8lNp9TvOyt57H8qXdmYpExO0gkihLQQ7ouiIO4V62Q13iXaRgf8Dji7iQ5wfHbxOY/TxMQpwt4uGnYlmJKHg0mqYNoBf/HagBNdzchIVuP/wlWrCqRfNWfeD230uiIrVK65uMCLi7ZcXlyUkxW52jks2RFd8+FK/JH8Syjn7RovNN4F0brf3Y8MUxqLLzgPls31lsLOv84VK5CA+/HPk3ulJ8qzOiWMjtAppdjhYEYRec+zmktgrcTp2kTVCOMX5TuowoTqEPo8Kgp1qkmSPxwUUviiotWdEGWElAEoesw1qmu/3PAVAoog9s9Fra0oxyrfU42+tzDlNldJsWcySlk2TFyFS4z/plAq8aGuzzGeWKdS/forGYvpEiGmorg8xEoadvl0B9LOcG/PZ061u5N2nCobqr9DSvoaw+fG8tG1l89OrYAXaYhdK/6XBLAZs47I78FehIn6kPm7E/Boz0ESs3bvKGUkcAsE9w+FgTldtU7hC9Z/zSAprPXf2NTyaWsKEb0kFtKhhb6ILXJ5dx1P9ZGGi2TruTqlTst/z9D0dUN95zDmUNZYMYR60dC2gGklHYd9YeHR72tQf9CCB5S6Qqo/DN4n/S9qHt+Fpn8zGKYQq9eT3CPTzrRLpXuoHnecLpDbIUJzl+boZQbwCECfR+BBJT8oQnv6miDj3+vy0CaYmY+XWiWvuCwiG3N1oeUx9WTNMfm2Xd6Y8pevU+U5meho5eMV1SP1uU19B+CpUjnv8RHv8wkf8Ft+zvf5BT/At/Qrfma+YPFrfsLx1PyIv+GH/D1/xl/yj/wTf84f8R/8Kf/Mv/JX/Dt/wV/zt/wd/8C/8G9cojdInmBZkDyUPJY8xVcXyYf4jiL5SJKtIzRw1PYbrQhLPDYNKucHsuPQ6NLo0ejbXfQUXKFlGl0aPRp9p6vCt+PSMo0ujR6NvqvCBWe0TKNLo0ej76mfSPAvLdPo0ujR6NPPJLJTpWUaXRo9Gv2q+rFEdmq0TKNLo0ejT7+XyE6dlml0afRo9OuqvuErgew0iIJGl0aPRr/RLQdWim3NbLqHKclRzao1wA1N2kCjS6NHo99UG6ZqQ5pvIL2qDwxKgeqzAqlYAwZxDeIaxDOIZxDfIL5GBISBNVSSeoujxYHVU8hwIds1bIxsAzgGcQ3iGsRbbDKIbxDfy2WngTVSkvoL2dPA6itktJDt55uqRrYBHIO4BnEN4hnEM4hvEL+ayx4G1kRJGixk9wJroJDJQnYt31Q3sg3gGMQ1iGsQzyCeQXyD+PVc9iiwQiUpXsjuB1askHAhu5FvahrZBnAM4hrENYhnEM8gvkF8jdxShPJzikT+Ash92m1/Rg61pxoL/hpokqNOjl4CeVi77c3IwxTa5MdAkxy1c3QqgXyu3W7OyAsV7GHmAJrlsJPDn4H8Eq/fmJFjIuz4/CvQxMB2Dj+jLKF0pfyR1MVfUmrQmJtj+0DuiaA7I49Vwmx+ATQxsJfDb4F8mF49yIkV7PJ3QBMDuzl8BOTWCKtrewQ7Tf4GaGJgL4d76tq+wpVIXx/axgwKNMthN4eFpEyFGlUifZKIWZiyWw5WNfgRKBra7dqMokGBNf4JaJKjfo4eAIUHHo10pGGH3wBNDFzN4Q9AMYRwdUZBpC5S51+AJgb2c/gQKKzwHsqsPsEefw/0bNCqRn9SnkVQ2bSuMJ//ouSaYzWNqS+aKsoQVbp0CG5iHQKaGLiu4edAkYioOphLaJ0/Ano2aE2jV0Axiih5ENE6Dj8Dmhi4lsPfgMIWYRUMPsENLI1AEwPXNfyKagCC9ZmK2z31tfU7pfkca2jsGiicEVTWdIjScfkJ0MTAjRyOlTBX4YqFS7CLvRDBDQM3c/gHUBpot5UyPY36/CnQJEcbOXoKlCDQnnQLfY4GfwI0MXAjh+l17jbI9tkBlSE4D7ILdqNLEfwMsmt2qcsR/AqyE3asSxI8C7KP7LkuS/AyyD6xR7o0wasge8He6vIE34PsNXunSxQIGWSRZNhzUA6ABOehZKmkYgT7QXbArqggwUWQ3bAzXZTgOsgu2ZEuTHASZMfsjS5O8DHInrMfukDBpyB7xJ7qIgUvguwt+6ALFbwOsnfsiy5WEKHUWLKp1DULQpynkg1p3oWDILtip1Sa4CbIztgTXZ7gMsiO2KEuUXAcZG/Ye12m4HmQ/WCfdamCR0H2lH3V5QreBtkH9k2XLHgXZF+YlLpuQYxip5L1pC5fkOJ8KNlIUoWCqyA7ZbdUpeAsyJ6wc12p4CjIDtlPXa3gTZC9Z790xYIfQfaZPdNVC54G2Vf2Ulcu+BBk39grXb3gS5BJyb7rEgZTFNuTTEhdyWCI85FkiaRiBadBdsv2qWDBkyA7Zxe6aMFhkP1k17pwwfsg+8VOdPGCz0H2jH3UBQy+BtlL9kkXMfgWZK/YC13IQKKg7+y1rmbQw5mQLJK6qMEI54lkocx7pLH6qUu3SfiIbf68pf8/T0X9HAR387WfOU6KX7QKlJ2Tjuyqn4To79wq8/z/QQwTIfANqkBabv0/nVLgIg=="},
            'sidh.js': {"requiresNode":false,"requiresBrowser":true,"minify":false,"code":"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"},
            'sjcl.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"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"},
    };

    /**
     * @desc Compressed Diceware word list provided by the ETF for passphrase generation.
     * @type {string}
     */
    const DICEWARE_WORD_LIST =
        `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`;

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
            return '2.0.2';
        }

        /**
         * @public
         * @desc Starts the script execution. This is called by BetterDiscord if the plugin is enabled.
         */
        start() {
            /* Validate location startup. */
            if( !_discordCrypt._ensureProperStartup() )
                return;

            /* Perform idiot-proof check to make sure the user named the plugin `discordCrypt.plugin.js` */
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
                /* Hook the necessary functions required for functionality. */
                _discordCrypt._hookSetup();

                /* Load the master password. */
                _discordCrypt._loadMasterPassword();

                /* Don't do anything further till we have a configuration file. */
                return;
            }

            /* Don't check for updates if running a debug version. */
            if ( !_discordCrypt._shouldIgnoreUpdates( this.getVersion() ) && _configFile.automaticUpdates ) {
                /* Check for any new updates. */
                _discordCrypt._checkForUpdates();

                /* Add an update handler to check for updates every 60 minutes. */
                _updateHandlerInterval = setInterval( () => {
                    _discordCrypt._checkForUpdates();
                }, 3600000 );
            }

            /* Block tracking and analytics. */
            _discordCrypt._blockTracking();

            /* Start the garbage collector. */
            _discordCrypt._initGarbageCollector();
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

            /* Unload the garbage collector. */
            clearInterval( _garbageCollectorInterval );

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
                /* Whether to automatically accept incoming key exchanges. */
                autoAcceptKeyExchanges: true,
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
                up1Host: UP1_FILE_HOST,
                /* Contains the API key used for transactions with the Up1 host. */
                up1ApiKey: UP1_FILE_HOST_API_KEY,
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
            // noinspection JSUnresolvedVariable
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
            // noinspection JSUnresolvedVariable
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
            // noinspection JSUnresolvedVariable
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
         * @property {string} primary The primary password.
         * @property {string} secondary The secondary password.
         */
        static _updatePasswords( primary, secondary ) {
            /* Don't save if the password overlay is not open. */
            if ( $( '#dc-overlay-password' ).css( 'display' ) !== 'block' )
                return;

            let id = _discordCrypt._getChannelId();

            /* Check if a primary & secondary password has actually been entered. */
            if ( !primary || !primary.length || !secondary || !secondary.length ) {
                _configFile.channels[ id ].primaryKey =
                    _configFile.channels[ id ].secondaryKey = null;

                /* Disable auto-encrypt for that channel */
                _discordCrypt._setAutoEncrypt( false );
            }
            else {
                /* Update the password field for this id. */
                _configFile.channels[ id ].primaryKey = primary;
                _configFile.channels[ id ].secondaryKey = secondary;

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
         * @desc Ensures the client starts up on a non-channel location for proper functioning.
         *      If the user is not on a whitelisted channel, the plugin will alert them then
         *          force-reload the Electron application.
         * @return {boolean} Returns true if the location is correct.
         */
        static _ensureProperStartup() {
            const electron = require( 'electron' );

            /* Due to how BD loads the client, we need to start on a non-channel page to properly hook events. */
            if( [ '/channels/@me', '/activity', '/library', '/store' ].indexOf( window.location.pathname ) === -1 ) {
                /* Send a synchronous alert to indicate the importance of this. */
                electron.ipcRenderer.sendSync(
                    'ELECTRON_BROWSER_WINDOW_ALERT',
                    `It seems that Discord has not been loaded on the Games or Friends tab.\n` +
                    `DiscordCrypt requires Discord to load on the Games or Friends tab to work correctly.\n` +
                    `I'll reload the client once you click OK so that it starts on the correct tab.\n\n` +
                    `\tPath: ${window.location.pathname}`,
                    'DiscordCrypt Error'
                );

                /* Relaunch the app completely. */
                electron.remote.app.relaunch();
                electron.remote.app.exit();

                return false;
            }

            return true;
        }

        /**
         * @private
         * @desc Loads the master-password unlocking prompt.
         */
        static _loadMasterPassword() {
            if ( $( '#dc-master-overlay' ).length !== 0 )
                return;

            /* Check if the database exists. */
            const cfg_exists = _discordCrypt._configExists();

            const action_msg = cfg_exists ? 'Unlock Database' : 'Create Database';

            /* Construct the password updating field. */
            $( document.body ).prepend( _discordCrypt.__zlibDecompress( UNLOCK_HTML ) );

            const pwd_field = $( '#dc-db-password' );
            const unlock_btn = $( '#dc-unlock-database-btn' );
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
            pwd_field.on( "keydown", ( e => {
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
                    action_msg
                )
            );
        }

        /**
         * @private
         * @desc Performs an async update checking and handles actually updating the current version if necessary.
         */
        static _checkForUpdates() {
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
                        $( '#dc-overlay-update' ).css( 'display', 'block' );

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
            $( '#dc-auto-accept-keys' ).prop( 'checked', _configFile.autoAcceptKeyExchanges );
            $( '#dc-settings-cipher-mode' ).val( _configFile.encryptBlockMode.toLowerCase() );
            $( '#dc-settings-padding-mode' ).val( _configFile.paddingMode.toLowerCase() );
            $( '#dc-settings-encrypt-trigger' ).val( _configFile.encodeMessageTrigger );
            $( '#dc-settings-timed-expire' ).val( _configFile.timedMessageExpires );
            $( '#dc-settings-decrypted-prefix' ).val( _configFile.decryptedPrefix );
            $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );
            $( '#dc-settings-exchange-mode' ).val( _configFile.exchangeBitSize );

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

            /* Handle About tab selected. */
            $( '#dc-about-settings-btn' ).click( _discordCrypt._onAboutTabButtonClicked );

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

            /* Ask the user about their password generation preferences. */
            $( '#dc-generate-password-btn' ).click( _discordCrypt._onGeneratePassphraseClicked );

            /* Set whether auto-encryption is enabled or disabled. */
            dc_lock_btn.click( _discordCrypt._onForceEncryptButtonClicked );
        }

        /**
         * @private
         * @desc Initializes additional threads needed for purging old data.
         */
        static _initGarbageCollector() {
            /* Set up the garbage collector. */
            _garbageCollectorInterval = setInterval( () => {
                /* Get the current time. */
                let now = Date.now();

                /* Remove all expired exchange entries. */
                for( let i in _globalSessionState ) {
                    /* Sanity check. */
                    if( !_globalSessionState[ i ].initiateTime )
                        continue;

                    /* Check if the exchange has expired. */
                    if( ( now - _globalSessionState[ i ].initiateTime ) > KEY_IGNORE_TIMEOUT ) {
                        /* Remove the entry. */
                        delete _globalSessionState[ i ];

                        /* Alert. */
                        global.smalltalk.alert(
                            'KEY EXCHANGE EXPIRED',
                            `The key exchange for the channel "${i}" has expired. Please retry again.`
                        );
                    }
                }

                /* Skip if the nonce is generate isn't found. */
                // noinspection JSUnresolvedVariable
                if( typeof _cachedModules.NonceGenerator.extractTimestamp !== 'function' ) {
                    _discordCrypt.log(
                        'Cannot clean expired key exchanges because a module couldn\'t be found.',
                        'warn'
                    );
                    return;
                }

                /* Iterate all channels stored. */
                for( let i in _configFile.channels ) {
                    /* Iterate all IDs being ignored. */
                    for( let id of _configFile.channels[ i ].ignoreIds ) {
                        /* Check when the message was sent. . */
                        // noinspection JSUnresolvedFunction
                        let diff_milliseconds = now - _cachedModules.NonceGenerator.extractTimestamp( id );

                        /* Delete the entry if it's greater than the ignore timeout. */
                        if( diff_milliseconds < 0 || diff_milliseconds > KEY_IGNORE_TIMEOUT ) {
                            /* Quickly log. */
                            _discordCrypt.log( `Deleting old key exchange message "${id}"` );

                            /* Remove the entry. */
                            delete _configFile.channels[ i ].ignoreIds[
                                _configFile.channels[ i ].ignoreIds.indexOf( id )
                            ];
                        }
                    }

                    /* Remove all empty entries. */
                    _configFile.channels[ i ].ignoreIds = _configFile.channels[ i ].ignoreIds.filter( e => e );
                }

                /* Update the configuration to the disk. */
                _discordCrypt._saveConfig();

            }, 10000 );

            /* Setup the timed message handler to trigger every 5 seconds. */
            _timedMessageInterval = setInterval( () => {
                /* Get the current time. */
                let now = Date.now();

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
                    if ( e.expireTime < now ) {
                        /* Quickly log. */
                        _discordCrypt.log( `Deleting timed message "${_configFile.timedMessages[ i ].messageId}"` );

                        try {
                            /* Delete the message. This will be queued if a rate limit is in effect. */
                            _discordCrypt._deleteMessage( e.channelId, e.messageId, _cachedModules );
                        }
                        catch ( e ) {
                            /* Log the error that occurred. */
                            _discordCrypt.log( `${e.messageId}: ${e.toString()}`, 'warn' );
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
         * @private
         * @desc Sets up the hooking methods required for plugin functionality.
         */
        static _hookSetup() {
            /* Scan for any existing method hooks. */
            if( !global.discordCrypt__hooked ) {
                /* Hooks can only be done once. Define a global property that indicates this. */
                global.discordCrypt__hooked = {};
                _Object.freeze( global.discordCrypt__hooked );
            }
            else {
                /* Reload since we need fresh hooks. */
                window.location.pathname = '/channels/@me';
                return;
            }

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
                );

                /* Request the image resolver. */
                let ImageResolver = searcher.findByUniqueProperties( [ 'getImageSrc', 'getSizedImageSrc' ] );

                /* Patch methods responsible for retrieving images to allow passing data URLs for attachments. */
                const ImageDataSrcPatch = ( patchData ) => {
                    if(
                        patchData.methodArguments[ 0 ] &&
                        patchData.methodArguments[ 0 ].indexOf( 'data:' ) === 0
                    )
                        patchData.returnValue = patchData.methodArguments[ 0 ];
                };
                _discordCrypt._monkeyPatch( ImageResolver, 'getImageSrc', { after: ImageDataSrcPatch } );
                _discordCrypt._monkeyPatch( ImageResolver, 'getSizedImageSrc', { after: ImageDataSrcPatch } );
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
         *      This can be called multiple times for a single event since this hooks:
         *          dispatch, maybeDispatch and dirtyDispatch.
         * @param {Object} event The event that occurred.
         */
        static _onDispatchEvent( event ) {
            let handled = false;

            try {
                /* Check if a handler exists for the event type and call it. */
                for( let i = 0; i < _eventHooks.length; i++ )
                    if( event.methodArguments[ 0 ].type === _eventHooks[ i ].type ) {
                        _eventHooks[ i ].callback( event );
                        handled = true;
                    }
            }
            catch( e ) {
                /* Ignore. */
            }

            /* If not handled by a hook, assume the position! ( Pun intended. ) */
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
            if ( _discordCrypt._getChannelId() === id ) {
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

                /* Delays are required due to windows being loaded async. */
                setTimeout(
                    () => {
                        /* Update the lock icon since it is local to the channel */
                        _discordCrypt._updateLockIcon( _self );

                        /* Add the toolbar. */
                        _discordCrypt._loadToolbar();
                    },
                    1
                );
            }

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
            /* Pretend no message was received till the configuration is unlocked. */
            ( async () => {
                /* Wait for the configuration file to be loaded. */
                while( !_configFile )
                    await ( new Promise( r => setTimeout( r, 1000 ) ) );

                /* Update the original object with any applicable changes. */
                event.methodArguments[ 0 ].message = _discordCrypt._decryptMessage(
                    event.methodArguments[ 0 ].channelId || event.methodArguments[ 0 ].message.channel_id,
                    event.methodArguments[ 0 ].message
                );

                /* Check if any file upload links are present in the decrypted content. */
                let attachments = _discordCrypt.__up1ExtractValidUp1URLs( event.methodArguments[ 0 ].message.content );

                /* Call the original method if we don't need to download and decrypt any files. . */
                if( !attachments.length )
                    event.originalMethod.apply( event.thisObject, event.methodArguments );

                /* Resolve each attachment. We only do this for messages that can be viewed to save bandwidth. */
                let resolvedCount = 0;
                for( let i = 0; i < attachments.length; i++ ) {
                    /* Slice off the seed. */
                    let seed = attachments[ i ]
                        .split( `${_configFile.up1Host}/#` )
                        .join( '' )
                        .split( `|${_configFile.encodeMessageTrigger}` )[ 0 ];

                    /* Download and decrypt the blob. */
                    ( async function() {
                        await _discordCrypt.__up1DecryptDownload(
                            seed,
                            _configFile.up1Host,
                            global.sjcl,
                            ( result ) => {
                                /* Bail on error. */
                                if( typeof result !== 'object' ) {
                                    resolvedCount += 1;
                                    return;
                                }

                                /* Build the attachment. */
                                let attachment = {
                                    id: _discordCrypt._getNonce(),
                                    filename: result.header.name,
                                    size: result.blob.size,
                                    url: attachments[ i ],
                                };

                                /* If the attachment is an image, get the width and height of it. */
                                if( result.header.mime.indexOf( 'image/' ) !== -1 ) {
                                    /* Create a new DataURL image to extract the dimensions from. */
                                    let img = new Image();
                                    img.src = `data:${result.header.mime};base64,${result.data.toString( 'base64' )}`;

                                    /* Store the dimensions. */
                                    attachment.width = img.width;
                                    attachment.height = img.height;

                                    /* Convert to a compatible data URL. */
                                    attachment.url = img.src;
                                }

                                /* Create a new attachment object or add it to the existing array. */
                                if( !event.methodArguments[ 0 ].message.attachments )
                                    event.methodArguments[ 0 ].message.attachments = [ attachment ];
                                else
                                    event.methodArguments[ 0 ].message.attachments.push( attachment );

                                /* Increment parsed count. */
                                resolvedCount += 1;
                            }
                        );
                    } )();
                }

                /* Wait till all attachments have been parsed. */
                while( resolvedCount !== attachments.length )
                    await ( new Promise( r => setTimeout( r, 1000 ) ) );

                /* Add the message to the list. */
                event.originalMethod.apply( event.thisObject, event.methodArguments );
            } )();
        }

        /**
         * @private
         * @desc The event handler that fires when a channel's messages are to be loaded.
         * @param {Object} event The channel loading event object.
         * @return {Promise<void>}
         */
        static _onIncomingMessages( event ) {
            /**
             * @type {string}
             */
            let id = event.methodArguments[ 0 ].channelId;
            /**
             * @type {Message[]}
             */
            let messages = event.methodArguments[ 0  ].messages;

            /* Pretend no message was received till the configuration is unlocked. */
            ( async () => {
                /* Wait for the configuration file to be loaded. */
                while ( !_configFile )
                    await ( new Promise( r => setTimeout( r, 1000 ) ) );

                /* Iterate all messages being received. */
                for ( let i = 0; i < messages.length; i++ ) {
                    /* Attempt to decrypt the message content. */
                    messages[ i ] = _discordCrypt._decryptMessage(
                        id,
                        messages[ i ]
                    );

                    /* Make sure the string has an actual length or pretend the message doesn't exist. */
                    if( !messages[ i ].content.length && !messages[ i ].embeds )
                        delete messages[ i ];
                }

                /* Filter out any deleted messages and apply any applicable updates. */
                event.methodArguments[ 0 ].messages = messages.filter( ( i ) => i );

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
            let r, cR;

            ( async () => {
                /* Wait till the configuration file has been loaded before parsing any messages. */
                await ( async () => {
                    while( !_configFile )
                        await ( new Promise( r => setTimeout( r, 1000 ) ) );
                } )();

                /* Copy the message object to a variable for easier parsing. */
                let message = event.methodArguments[ 0 ].message;

                /* Try encrypting the message content. */
                cR = _discordCrypt._tryEncryptMessage( message.content, false, message.channelId );

                /* Apply the message content if valid. */
                if( typeof cR !== 'boolean' && cR.length > 0 )
                    message.content = cR[ 0 ].message;

                /* If this message contains an embed, try encrypting also. */
                if( message.embed ) {
                    /* If the message contains a description, encrypt it. */
                    if( message.embed.description ) {
                        r = _discordCrypt._tryEncryptMessage( message.embed.description, false, message.channelId );

                        /* If valid, apply the updated result. */
                        if( typeof r !== 'boolean' && r.length === 1 )
                            message.embed.description = r[ 0 ].message;
                    }

                    /* Try encrypting fields if present. */
                    for( let i = 0; message.embed.fields && i < message.embed.fields.length; i++ ) {
                        /* First encrypt the field name. */
                        r = _discordCrypt._tryEncryptMessage(
                            message.embed.fields[ i ].name,
                            false,
                            message.channelId
                        );

                        /* Apply the result if applicable. */
                        if( typeof r !== 'boolean' && r.length === 1 )
                            message.embed.fields[ i ].name = r[ 0 ].message;

                        /* Next encrypt the field value. */
                        r = _discordCrypt._tryEncryptMessage(
                            message.embed.fields[ i ].value,
                            false,
                            message.channelId
                        );

                        /* Apply the result if applicable. */
                        if( typeof r !== 'boolean' && r.length === 1 )
                            message.embed.fields[ i ].value = r[ 0 ].message;

                    }
                }

                /* Update the message object to reflect any changes. */
                event.methodArguments[ 0 ].message = message;

                /* Call the original dispatching method. */
                event.originalMethod.apply( event.thisObject, event.methodArguments );

                /* Dispatch any additional packets containing additional content. */
                if( cR.length !== 1 ) {
                    for( let i = 1; i < cR.length; i++ )
                        _discordCrypt._dispatchMessage( cR[ i ].message, message.channelId );
                }
            } )();
        }

        /**
         * @private
         * @desc Attempts to decrypt a message object with any encrypted content or embeds.
         * @param {string} id The channel ID of the message.
         * @param {Message} message The message object to decrypt.
         * @return {Message} Returns the passed message object with any decrypted content if applicable.
         */
        static _decryptMessage( id, message ) {
            /**
             * @desc Decrypts the message content specified, updates any mentioned users and returns the result.
             * @param {string} id The channel ID of the message being decrypted.
             * @param {string} content The content to decrypt.
             * @param {Message} message The message object.
             * @param {string} primary_key The primary key used for decryption.
             * @param {string} secondary_key The secondary key used for decryption.
             * @return {string|boolean} Returns the decrypted string on success or false on failure.
             * @private
             */
            const _decryptMessageContent = ( id, content, message, primary_key, secondary_key ) => {
                let r = _discordCrypt._parseMessage(
                    content,
                    message,
                    primary_key,
                    secondary_key,
                    _configFile.decryptedPrefix
                );

                /* Assign it to the object if valid. */
                if( typeof r === 'string' && r.length ) {
                    /* Calculate any mentions. */
                    let notifications = _discordCrypt._getMentionsForMessage( r, id );

                    /* Add any user mentions. */
                    if( notifications.mentions.length ) {
                        /* Append to the existing list if necessary. */
                        if( !message.mentions )
                            message.mentions = notifications.mentions;
                        else
                            message.mentions = message.mentions
                                .concat( notifications.mentions )
                                .filter( ( e, i, s ) => i === s.indexOf( e ) );
                    }

                    /* Add any role mentions. */
                    if( notifications.mention_roles.length ) {
                        /* Append to the existing list if necessary. */
                        if( !message.mention_roles )
                            message.mention_roles = notifications.mention_roles;
                        else
                            message.mention_roles = message.mention_roles
                                .concat( notifications.mention_roles )
                                .filter( ( e, i, s ) => i === s.indexOf( e ) );
                    }

                    /* Update the "@everyone" field if necessary. */
                    message.mention_everyone = message.mention_everyone || notifications.mention_everyone;
                }

                return r;
            };

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

            /* Check if the content is in the valid format. */
            if( _discordCrypt._isFormattedMessage( message.content ) ) {
                /* Decrypt the content. */
                let r = _decryptMessageContent(
                    id,
                    message.content.substr( 1, message.content.length - 2 ),
                    message,
                    primary_key,
                    secondary_key
                );

                /* Update the content if necessary. */
                if( typeof r === 'string' )
                    message.content = r;
            }

            /* Parse any embed available. */
            for( let i = 0; message.embeds && i < message.embeds.length; i++ ) {
                /* Decrypt the description. */
                if(
                    message.embeds[ i ].description &&
                    _discordCrypt._isFormattedMessage( message.embeds[ i ].description )
                ) {
                    let r = _decryptMessageContent(
                        id,
                        message.embeds[ i ].description.substr( 1, message.embeds[ i ].description.length - 2 ),
                        message,
                        primary_key,
                        secondary_key
                    );

                    /* Apply on success. */
                    if( typeof r === 'string' )
                        message.embeds[ i ].description = r;
                }

                /* Decrypt any embed fields. */
                for( let j = 0; message.embeds[ i ].fields && j < message.embeds[ i ].fields.length; j++ ) {
                    /* Skip fields without formatted name. */
                    if( _discordCrypt._isFormattedMessage( message.embeds[ i ].fields[ j ].name ) ) {
                        /* Decrypt the name. */
                        let r = _decryptMessageContent(
                            id,
                            message.embeds[ i ].fields[ j ].name.substr(
                                1,
                                message.embeds[ i ].fields[ j ].name - 2
                            ),
                            message,
                            primary_key,
                            secondary_key
                        );

                        /* Apply on success. */
                        if( typeof r === 'string' )
                            message.embeds[ i ].fields[ j ].name = r;
                    }
                    /* Skip fields without formatted value. */
                    if( _discordCrypt._isFormattedMessage( message.embeds[ i ].fields[ j ].value ) ) {
                        /* Decrypt the name. */
                        let r = _decryptMessageContent(
                            id,
                            message.embeds[ i ].fields[ j ].value.substr(
                                1,
                                message.embeds[ i ].fields[ j ].value.length - 2
                            ),
                            message,
                            primary_key,
                            secondary_key
                        );

                        /* Apply on success. */
                        if( typeof r === 'string' )
                            message.embeds[ i ].fields[ j ].value = r;
                    }
                }
            }

            /* Return the ( possibly modified ) object. */
            return message;
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
         * @desc Detects and returns all roles & users mentioned in a message.
         *      Shamelessly "stolen" from BetterDiscord team. Thanks guys. :D
         * @param {string} message The input message.
         * @param {string} [id] The channel ID this message will be dispatched to.
         * @return {MessageMentions}
         */
        static _getMentionsForMessage( message, id ) {
            /* Patterns for capturing specific mentions. */
            const user_mentions = /<@!?([0-9]{10,24})>/g,
                role_mentions = /<@&([0-9]{10,24})>/g,
                everyone_mention = /(?:\s+|^)@everyone(?:\s+|$)/;

            /* Actual format as part of a message object. */
            let result = {
                mentions: [],
                mention_roles: [],
                mention_everyone: false
            };

            /* Get the channel's ID. */
            id = id || _discordCrypt._getChannelId();

            /* Get the channel's properties. */
            let props = _discordCrypt._getChannelProps( id );

            /* Check if properties were retrieved. */
            if( !props )
                return result;

            /* Parse the message into ID based format. */
            message = _cachedModules.MessageCreator.parse( props, message ).content;

            /* Check for user tags. */
            if( user_mentions.test( message ) ) {
                /* Retrieve all user IDs in the parsed message. */
                result.mentions = message
                    .match( user_mentions )
                    .map( m => {
                        return { id: m.replace( /[^0-9]/g, '' ) }
                    } );
            }

            /* Gather role mentions. */
            if( role_mentions.test( message ) ) {
                /* Retrieve all role IDs in the parsed message. */
                result.mention_roles = message.match( role_mentions ).map( m => m.replace( /[^0-9]/g, '' ) );
            }

            /* Detect if mentioning everyone. */
            result.mention_everyone = everyone_mention.test( message );

            return result;
        }

        /**
         * @private
         * @desc Handles a key exchange request that has been accepted.
         * @param {Message} message The input message object.
         * @param {PublicKeyInfo} remoteKeyInfo The public key's information.
         * @return {string} Returns the resulting message string.
         */
        static _handleAcceptedKeyRequest( message, remoteKeyInfo ) {
            let encodedKey, algorithm;

            /* If a local key doesn't exist, generate one and send it. */
            if(
                !_globalSessionState.hasOwnProperty( message.channel_id ) ||
                !_globalSessionState[ message.channel_id ].privateKey
            ) {
                /* Create the session object. */
                _globalSessionState[ message.channel_id ] = {};
                _globalSessionState[ message.channel_id ].initiateTime = Date.now();

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

            /* Extract the algorithm for later logging. */
            algorithm = `${_globalSessionState[ message.channel_id ].localKey.algorithm.toUpperCase()}-`;
            algorithm += `${_globalSessionState[ message.channel_id ].localKey.bit_length}`;

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
            return '🔏 **[ SESSION ]** *ESTABLISHED NEW SESSION* !!!\n\n' +
                `Algorithm: **${algorithm}**\n` +
                `Primary Entropy: **${_discordCrypt.__entropicBitLength( keys.primaryKey )} Bits**\n` +
                `Secondary Entropy: **${_discordCrypt.__entropicBitLength( keys.secondaryKey )} Bits**\n`;
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
                return '🚫 **[ ERROR ]** `INVALID PUBLIC KEY !!!`';

            /* Validate functions. */
            // noinspection JSUnresolvedVariable
            if(
                !_cachedModules.UserStore ||
                typeof _cachedModules.UserStore.getCurrentUser !== 'function' ||
                typeof _cachedModules.UserStore.getUser !== 'function' ||
                typeof _cachedModules.ChannelStore.getChannels !== 'function'
            )
                return '🚫 **[ ERROR ]** `CANNOT RESOLVE DEPENDENCY MODULE !!!`';

            /* Make sure that this key wasn't somehow sent in a guild or group DM. */
            // noinspection JSUnresolvedFunction
            let channels = _cachedModules.ChannelStore.getChannels();
            if( channels && channels[ message.channel_id ] && channels[ message.channel_id ].type !== 1 )
                return '🚫 **[ ERROR ]** `INCOMING KEY EXCHANGE FROM A NON-DM !!!`';

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
                /* By default, we use the locally defined key to retrieve the information. */
                let k;

                /* If it is, ensure we have a private key for it. */
                if(
                    !_globalSessionState.hasOwnProperty( message.channel_id ) ||
                    !_globalSessionState[ message.channel_id ].privateKey
                ) {
                    /* This is a local public key that has already been ACK'd. We can ignore it. */
                    k = remoteKeyInfo;
                }
                else
                    k = _globalSessionState[ message.channel_id ].localKey;

                return '🔏 **[ SESSION ]** *OUTGOING KEY EXCHANGE*\n\n' +
                    `Algorithm: **${k.algorithm.toUpperCase()}-${k.bit_length}**\n` +
                    `Checksum: **${k.fingerprint}**`;
            }

            /* Be sure to add the message ID to the ignore list. */
            _configFile.channels[ message.channel_id ].ignoreIds.push( message.id );
            _discordCrypt._saveConfig();

            /* Check if this is an incoming key exchange or a resulting message. */
            if( _globalSessionState.hasOwnProperty( message.channel_id ) )
                return _discordCrypt._handleAcceptedKeyRequest( message, remoteKeyInfo );

            /* Check if we need to prompt. */
            if( _configFile.autoAcceptKeyExchanges )
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
                        /* Make sure the key didn't expire by the time they accepted it. */
                        if( ( Date.now() - Date.parse( message.timestamp ) ) > KEY_IGNORE_TIMEOUT )
                            returnValue = '🚫 **[ ERROR ]** SESSION KEY EXPIRED';
                        else {
                            /* The user accepted the request. Handle the key exchange.  */
                            returnValue = _discordCrypt._handleAcceptedKeyRequest( message, remoteKeyInfo );
                        }
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
         * @desc Parses a raw message and returns the decrypted result.
         * @param {string} content The message content to parse.
         * @param {Message} [message] The message object.
         * @param {string} primary_key The primary key used to decrypt the message.
         * @param {string} secondary_key The secondary key used to decrypt the message.
         * @param {string} [prefix] Messages that are successfully decrypted should have this prefix prepended.
         * @param {boolean} [allow_key_parsing] Whether to allow key exchange parsing.
         * @return {string|boolean} Returns false if a message isn't in the correct format or the decrypted result.
         */
        static _parseMessage( content, message, primary_key, secondary_key, prefix, allow_key_parsing = true ) {
            /* Skip if the message is <= size of the total header. */
            if ( content.length <= 12 )
                return false;

            /* Split off the magic. */
            let magic = content.slice( 0, 4 );

            /* If this is a public key, just add a button and continue. */
            if ( allow_key_parsing && magic === ENCODED_KEY_HEADER )
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
                return '🚫 **[ ERROR ]** `AUTHENTICATION OF CIPHER TEXT FAILED !!!`';
            case 2:
                return '🚫 **[ ERROR ]** `FAILED TO DECRYPT CIPHER TEXT !!!`';
            default:
                return '🚫 **[ ERROR ]** `DECRYPTION FAILURE. INVALID KEY OR MALFORMED MESSAGE !!!`';
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
                        `Failed to hook method: ${Array.isArray( name ) ? name[ 0 ] : name}\n${e}`,
                        'warn'
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
                        `Failed to hook method: ${Array.isArray( name ) ? name[ 0 ] : name}\n${e}`,
                        'warn'
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
         * @return {Function}
         */
        static _onMasterUnlockButtonClicked( unlock_btn, cfg_exists, pwd_field, action_msg ) {
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
                // noinspection JSUnresolvedFunction
                let pwd = global.scrypt.crypto_scrypt
                (
                    Buffer.from( password ),
                    Buffer.from( global.sha3.sha3_256( password ), 'hex' ),
                    16384,
                    16,
                    1,
                    32
                );

                if ( pwd ) {
                    /* To test whether this is the correct password or not, we have to attempt to use it. */
                    _masterPassword = Buffer.from( pwd );

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

                        /* Reset the text of the button after 1 second. */
                        setTimeout( ( function () {
                            unlock_btn.text( action_msg );
                            unlock_btn.attr( 'disabled', false );
                        } ), 1000 );

                        /* Proceed no further. */
                        return;
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
                else {

                    /* Update the button's text. */
                    if ( cfg_exists )
                        unlock_btn.text( 'Invalid Password!' );
                    else
                        unlock_btn.text( `Error: Scrypt Failed!}` );

                    /* Clear the text field. */
                    pwd_field.val( '' );

                    /* Reset the text of the button after 1 second. */
                    setTimeout( ( function () {
                        unlock_btn.text( action_msg );
                    } ), 1000 );

                    _discordCrypt.log( error.toString(), 'error' );
                }
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
                        `${file_url}${
                            send_deletion_link ?
                                '\n\nDelete URL: ' + deletion_link :
                                ''
                        }`,
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
                let name = '', icon, id = prop;

                /* Skip channels that don't have an ID. */
                if ( !channels[ id ] )
                    continue;

                /* Skip channels that don't have a custom password. */
                if(  !_configFile.channels[ id ].primaryKey || !_configFile.channels[ id ].secondaryKey )
                    continue;

                /* Choose a default icon. */
                icon = 'https://cdn.discordapp.com/icons/444361997811974144/74cb26731242af7fdd60a62c29dc7560.png';

                /* Check for the correct channel type. */
                if ( channels[ id ].type === 0 ) {
                    /* GUILD_TEXT */
                    let guild = guilds[ channels[ id ].guild_id ];

                    /* Resolve the name as a "Guild ( #Channel )" format. */
                    name = `${guild.name} ( #${channels[ id ].name} )`;

                    /* Update the icon. */
                    if( guild.icon )
                        icon = `https://cdn.discordapp.com/icons/${channels[ id ].guild_id}/${guild.icon}.png`;
                }
                else if ( channels[ id ].type === 1 ) {
                    /* DM */
                    // noinspection JSUnresolvedVariable
                    let user = users[ channels[ id ].recipients[ 0 ] ];

                    /* Indicate this is a DM and give the full user name. */
                    name = `@${user.username}`;

                    /* Update the icon. */
                    if( user.id && user.avatar )
                        icon = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`;
                }
                else if ( channels[ id ].type === 3 ) {
                    /* GROUP_DM */

                    /* Try getting the channel name first. */
                    if( channels[ id ].name )
                        name = channels[ id ].name;
                    else {
                        // noinspection JSUnresolvedVariable
                        let max = channels[ id ].recipients.length > 3 ? 3 : channels[ id ].recipients.length,
                            participants = '';

                        /* Iterate the maximum number of users we can display. */
                        for( let i = 0; i < max; i++ ) {
                            // noinspection JSUnresolvedVariable
                            let user = users[ channels[ id ].recipients[ i ] ];
                            participants += `@${user.username}#${user.discriminator} `;
                        }

                        /* List a maximum of three members. */
                        name = `${participants}`;
                    }

                    /* Update the icon. */
                    if( channels[ id ].icon )
                        icon = `https://cdn.discordapp.com/channel-icons/${id}/${channels[ id ].icon}.png`;
                }
                else
                    continue;

                /* Create the elements needed for building the row. */
                let element =
                        $( `<tr>
                                <td class="dc-ruler-align">
                                    <div class="dc-icon" style="background-image:url(${icon});"></div>
                                    <p>${name}</p>
                                </td>
                                <td>
                                    <div style="display:flex;"></div>
                                </td>
                            </tr>` ),
                    delete_btn = $( '<button>' )
                        .addClass( 'dc-button dc-button-small dc-button-inverse' )
                        .text( 'Delete Keys' ),
                    copy_btn = $( '<button>' )
                        .addClass( 'dc-button dc-button-small dc-button-inverse' )
                        .text( 'Copy Keys' ),
                    encrypt_icon = $( '<div>' )
                        .addClass( 'dc-tooltip' )
                        .css( 'background-color', 'transparent' )
                        .html(
                            Buffer.from(
                                _configFile.channels[ id ].autoEncrypt ? LOCK_ICON : UNLOCK_ICON,
                                'base64'
                            )
                                .toString( 'utf8' )
                        );

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

                    copy_btn.text( 'Copied' );

                    setTimeout( () => {
                        copy_btn.text( 'Copy Keys' );
                    }, 1000 );
                } );

                /* Handle toggling states. */
                encrypt_icon.click( function() {
                    /* Toggle the encryption state for the channel */
                    _configFile.channels[ id ].autoEncrypt = !_configFile.channels[ id ].autoEncrypt;

                    /* Save the configuration. */
                    _discordCrypt._saveConfig();

                    /* Update the icon. */
                    encrypt_icon.html(
                        Buffer.from(
                            _configFile.channels[ id ].autoEncrypt ? LOCK_ICON : UNLOCK_ICON,
                            'base64'
                        )
                            .toString( 'utf8' ) );
                } );

                /* Append the buttons to the Options column. */
                $( $( element.children()[ 1 ] ).children()[ 0 ] ).append( encrypt_icon );
                $( $( element.children()[ 1 ] ).children()[ 0 ] ).append( copy_btn );
                $( $( element.children()[ 1 ] ).children()[ 0 ] ).append( delete_btn );

                /* Append the entire entry to the table. */
                table.append( element );
            }

            /* Select the database settings. */
            _discordCrypt._setActiveSettingsTab( 1 );
        }

        /**
         * @private
         * @desc Selects the Security Settings tab and loads all blacklisted updates.
         */
        static _onSecurityTabButtonClicked() {
            /* Get the table to show blacklisted updates. */
            let table = $( '#dc-update-blacklist-entries' );

            /* Clear all entries. */
            table.html( '' );

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
                    global.openpgp.key.readArmored( _discordCrypt.__zlibDecompress( PGP_SIGNING_KEY ) ).then(
                        r => {
                            let key_id = Buffer.from( r.keys[ 0 ].primaryKey.fingerprint )
                                .toString( 'hex' )
                                .toUpperCase();

                            global.smalltalk.alert(
                                'Update Info',
                                `<strong>Version</strong>: ${updateInfo.version}\n\n` +
                                `<strong>Verified</strong>: ${updateInfo.valid ? 'Yes' : 'No'}\n\n` +
                                `<strong>Key ID</strong>: ${key_id}\n\n` +
                                `<strong>Hash</strong>: ${updateInfo.hash}\n\n` +
                                '<code class="hljs dc-code-block" style="background: none !important;">' +
                                `${updateInfo.signature}</code>`
                            );
                        }
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
         * @desc Selects the About tab.
         */
        static _onAboutTabButtonClicked() {
            /* Select the about tab. */
            _discordCrypt._setActiveSettingsTab( 3 );
        }

        /**
         * @private
         * @desc Toggles the automatic update checking function.
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
                            _discordCrypt._checkForUpdates();
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
         */
        static _onCheckForUpdatesButtonClicked() {
            /* Simply call the wrapper, everything else will be handled by this. */
            _discordCrypt._checkForUpdates();
        }

        /**
         * @private
         * @desc Opens a file dialog to import a JSON encoded entries file.
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
         * @desc Opens a file dialog to export a JSON encoded entries file.
         */
        static _onExportDatabaseButtonClicked() {
            /* Generate a random captcha to verify the user wants to do this.*/
            let captcha = _discordCrypt.__generateWordCaptcha();

            /* Alert the user before they do this. */
            global.smalltalk.prompt(
                'EXPORT WARNING',
                'Exporting your database is <b>DANGEROUS</b>.\n\n' +
                'You should only do this when <u>explicitly</u> directed by the plugin\'s developers.\n\n\n' +
                '<b>N.B. Exports will NOT be encrypted. Be responsible.</b>\n\n' +
                'Enter the following and click "OK" to export the database:\n\n\n' +
                `<p style="text-indent: 20px"><b>${captcha.captcha}</b></p>\n\n`,
                ''
            )
                .then(
                    ( value ) => {
                        /* Make sure the user entered the correct passphrase before continuing. */
                        if( value.toLowerCase().trim() !== captcha.passphrase ) {
                            setImmediate( _discordCrypt._onExportDatabaseButtonClicked );
                            return;
                        }

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
                    },
                    () => {
                        /* Ignored. */
                    }
                );
        }

        /**
         * @private
         * @desc Clears all entries in the database.
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
         */
        static _onSaveSettingsButtonClicked() {
            /* Cache jQuery results. */
            let dc_primary_cipher = $( '#dc-primary-cipher' ),
                dc_secondary_cipher = $( '#dc-secondary-cipher' ),
                dc_master_password = $( '#dc-master-password' ),
                dc_save_settings_btn = $( '#dc-settings-save-btn' );

            /* Update all settings from the settings panel. */
            _configFile.timedMessageExpires = parseInt( $( '#dc-settings-timed-expire' ).val() );
            _configFile.autoAcceptKeyExchanges = $( '#dc-auto-accept-keys' ).is( ':checked' );
            _configFile.exchangeBitSize = parseInt( $( '#dc-settings-exchange-mode' ).val() );
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
                // noinspection JSUnresolvedFunction
                let pwd = global.scrypt.crypto_scrypt
                (
                    Buffer.from( password ),
                    Buffer.from( global.sha3.sha3_256( password ), 'hex' ),
                    16384,
                    16,
                    1,
                    32
                );

                /* Enable the button. */
                dc_save_settings_btn.attr( 'disabled', false );

                if ( !pwd || typeof pwd !== 'string' || !pwd.length ) {
                    /* Alert the user. */
                    global.smalltalk.alert(
                        'DiscordCrypt Error',
                        'Error setting the new database password. Check the console for more info.'
                    );

                    _discordCrypt.log( error.toString(), 'error' );
                    return;
                }

                /* Now update the password. */
                _masterPassword = Buffer.from( pwd );

                /* Save the configuration file and update the button text. */
                _discordCrypt._saveSettings( dc_save_settings_btn );
            }
            else {
                /* Save the configuration file and update the button text. */
                _discordCrypt._saveSettings( dc_save_settings_btn );
            }
        }

        /**
         * @private
         * @desc Resets the user settings to their default values.
         */
        static _onResetSettingsButtonClicked() {
            /* Resets the configuration file and update the button text. */
            _discordCrypt._resetSettings( $( '#dc-settings-reset-btn' ) );

            /* Update all settings from the settings panel. */
            $( '#dc-secondary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );
            $( '#dc-primary-cipher' ).val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
            $( '#dc-auto-accept-keys' ).prop( 'checked', _configFile.autoAcceptKeyExchanges );
            $( '#dc-settings-cipher-mode' ).val( _configFile.encryptBlockMode.toLowerCase() );
            $( '#dc-settings-padding-mode' ).val( _configFile.paddingMode.toLowerCase() );
            $( '#dc-settings-encrypt-trigger' ).val( _configFile.encodeMessageTrigger );
            $( '#dc-settings-timed-expire' ).val( _configFile.timedMessageExpires );
            $( '#dc-settings-decrypted-prefix' ).val( _configFile.decryptedPrefix );
            $( '#dc-settings-exchange-mode' ).val( _configFile.exchangeBitSize );
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
            $( '#dc-overlay-update' ).css( 'display', 'none' );
        }

        /**
         * @private
         * @desc Adds the upper scoped update info to the blacklist, saves the configuration file and
         *      closes the update window.
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
            $( '#dc-overlay-update' ).css( 'display', 'none' );
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
         */
        static _onSavePasswordsButtonClicked() {
            let save_btn = $( '#dc-save-pwd' ),
                primary_password = $( "#dc-password-primary" ),
                secondary_password = $( "#dc-password-secondary" );

            /* Ensure both the primary and secondary password fields are specified. */
            if( !primary_password.val().length || !secondary_password.val().length ) {
                save_btn.text( 'Please Fill In Both Fields !' );

                /* Reset the button text after. */
                setTimeout( () => {
                    /* Reset text. */
                    save_btn.text( "Save Password" );
                }, 1000 );

                return;
            }

            /* Update the password and save it. */
            _discordCrypt._updatePasswords( primary_password.val(), secondary_password.val() );

            /* Update the text for the button. */
            save_btn.text( "Saved!" );

            /* Reset the text for the password button after a 1 second delay. */
            setTimeout( ( function () {
                /* Reset text. */
                save_btn.text( "Save Password" );

                /* Clear the fields. */
                primary_password.val( '' );
                secondary_password.val( '' );

                /* Close. */
                $( '#dc-overlay' ).css( 'display', 'none' );
                $( '#dc-overlay-password' ).css( 'display', 'none' );
            } ), 1000 );
        }

        /**
         * @private
         * @desc Resets passwords for the current channel or DM to their defaults.
         */
        static _onResetPasswordsButtonClicked() {
            let reset_btn = $( '#dc-reset-pwd' );

            /* Disable auto-encrypt for the channel */
            _discordCrypt._setAutoEncrypt( false );

            let id = _discordCrypt._getChannelId();

            /* Reset the configuration for this user and save the file. */
            _configFile.channels[ id ].primaryKey =
                _configFile.channels[ id ].secondaryKey = null;

            /* Save them. */
            _discordCrypt._saveConfig();

            /* Update the text for the button. */
            reset_btn.text( "Password Reset!" );

            setTimeout( ( function () {
                /* Reset text. */
                reset_btn.text( "Reset Password" );

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
         * @desc Prompts the user on their passphrase generation options.
         */
        static _onGeneratePassphraseClicked() {
            global.smalltalk.prompt(
                'GENERATE A SECURE PASSPHRASE',
                'Please enter how many words you\'d like this passphrase to have below.\n' +
                'Be advised that a minimum word length of <b><u>20</u></b> is recommended.\n\n',
                '20'
            ).then(
                ( value ) => {
                    /* Validate the value entered. */
                    if( typeof value !== 'string' || !value.length || isNaN( value ) ) {
                        global.smalltalk.alert( 'ERROR', 'Invalid number entered' );
                        return;
                    }

                    /* Generate the word list. */
                    let { entropy, passphrase } = _discordCrypt.__generateDicewarePassphrase( parseInt( value ) );

                    /* Alert the user. */
                    global.smalltalk.prompt(
                        `GENERATED A ${parseInt( value )} WORD LONG PASSPHRASE`,
                        `This passphrase contains approximately <b>${Math.round( entropy )} bits of entropy</b>.\n\n` +
                        'Please copy your generated passphrase below:\n\n',
                        passphrase
                    ).then(
                        () => {
                            /* Copy to the clipboard then close. */
                            require( 'electron' ).clipboard.writeText( passphrase );
                        },
                        () => {
                            /* Ignored. */
                        }
                    );
                },
                () => {
                    /* Ignored. */
                }
            );
        }

        /**
         * @private
         * @desc Copies the passwords from the current channel or DM to the clipboard.
         */
        static _onCopyCurrentPasswordsButtonClicked() {
            // noinspection JSUnresolvedVariable
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
            case 3:
                $( '#dc-about-settings-btn' ).addClass( 'active' );
                $( '#dc-about-settings-tab' ).css( 'display', 'block' );
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
            const fs = require( 'fs' );

            const BETTERDISCORD_PATH = '/BetterDiscord/plugins/';
            const MAC_PATH = `${process.env.HOME}/Library/Preferences`;
            const DEB_PATH = `${process.env.HOME}.config`;

            switch( process.platform ) {
            case 'win32':
                return `${process.env.APPDATA}${BETTERDISCORD_PATH}`;
            case 'darwin':
                return `${MAC_PATH}${BETTERDISCORD_PATH}`;
            case 'linux':
                if( fs.existsSync( process.env.XDG_CONFIG_HOME ) )
                    return `${process.env.XDG_CONFIG_HOME}${BETTERDISCORD_PATH}`;
                return `${DEB_PATH}${BETTERDISCORD_PATH}`;
            default:
                _discordCrypt.log( `Unsupported platform detected: ${process.platform} ...`, 'error' );
                throw 'DEAD';
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
            const changelog_url = `${base_url}/CHANGELOG`;
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
                    // noinspection JSUnresolvedFunction
                    let currentHash = global.sha3.sha3_256( localFile.replace( '\r', '' ) );
                    // noinspection JSUnresolvedFunction
                    updateInfo.hash = global.sha3.sha3_256( data.replace( '\r', '' ) );

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

                    // noinspection JSUnresolvedVariable
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
                            // noinspection JSUnresolvedVariable
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
         * @param {int} [channel_id] Sends the embedded message to this channel instead of the current channel.
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

                        // noinspection JSUnresolvedVariable
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
                _discordCrypt.log( `Hooking ${methodName} ...` );

            /* Backup the original method for unpatching or restoring. */
            let origMethod = what[ methodName ];

            /* If a method can't be found, handle appropriately based on if forcing patches. */
            if ( !origMethod ) {
                if ( !forcePatch ) {
                    /* Log and bail out. */
                    _discordCrypt.log(
                        `Can't find non-existent method '${displayName}.${methodName}' to hook.`,
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
                    _discordCrypt.log( `Unhooking method: '${displayName}.${methodName}' ...` );

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

            /* Make sure the method is marked as hooked. */
            // noinspection JSUnusedGlobalSymbols
            what[ methodName ].__monkeyPatched = true;
            what[ methodName ].displayName = `Hooked ${what[ methodName ].displayName || methodName}`;

            /* Save the unhook method to the object. */
            // noinspection JSUnusedGlobalSymbols
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
         * @desc Builds a random captcha phrase to validate user input.
         * @param {number} word_count The number of words to use for the captcha.
         * @return {{passphrase: string, captcha: string}}
         */
        static __generateWordCaptcha( word_count = 5 ) {
            /* Generator for determining which character set to choose from. */
            const randomBytes = require( 'crypto' ).randomBytes;

            /* Stores the result captcha. */
            let captcha = '';

            /* This uses a converter to transform the text. */
            const CONVERTER = [
                    /* REGULAR */
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',

                    /* SMALLCAPS */
                    'ᴀʙᴄᴅᴇғɢʜɪᴊᴋʟᴍɴᴏᴘǫʀsᴛᴜᴠᴡxʏᴢ',

                    /* SUPERSCRIPT */
                    'ᴬᴮᶜᴰᴱᶠᴳᴴᴵᴶᴷᴸᴹᴺᴼᴾQᴿˢᵀᵁνᵂˣʸᶻ'
                ],
                ALPHABET = CONVERTER[ 0 ].toLowerCase();

            /* Generate a random passphrase. */
            let passphrase = _discordCrypt.__generateDicewarePassphrase( word_count );

            /* Split the passphrase into words. */
            let words = passphrase.passphrase.split( ' ' );

            /* Iterate each word to build the captcha. */
            for( let i = 0; i < words.length; i++ ) {
                /* Generate a random sequence to pick the word list from. */
                let rand = randomBytes( words[ i ].length );

                /* Build a new word using the random word lists. */
                for( let j = 0; j < words[ i ].length; j++ )
                    captcha += CONVERTER[ rand[ j ] % CONVERTER.length ][ ALPHABET.indexOf( words[ i ][ j ] ) ];

                /* Add the space. */
                captcha += ' ';
            }

            /* Return the captcha and expected values. */
            return {
                passphrase: passphrase.passphrase,
                captcha: captcha.trim(),
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
                input.length < 32 &&
                !( new RegExp( /^(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W).*$/g ) ).test( input )
            ) {
                global.smalltalk.alert(
                    'Invalid Password Input',
                    'Your password <b>must be at least 8 characters</b> long and <u>must</u> contain ' +
                    'a combination of alpha-numeric characters both uppercase and lowercase ( A-Z, a-z, 0-9 ) ' +
                    'as well as at least one symbol <b>OR</b> be greater than 32 characters for the best security.' +
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
        static async __validatePGPSignature( message, signature, public_key ) {
            if( typeof global === 'undefined' || !global.openpgp )
                return false;

            let options = {
                message: global.openpgp.message.fromText( message ),
                signature: await global.openpgp.signature.readArmored( signature ),
                publicKeys: ( await global.openpgp.key.readArmored( public_key ) ).keys
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
                    _discordCrypt.log( `Running ${name} in current VM context ...` );
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
                    _discordCrypt.log( `Running ${name} in isolated VM context ...` );
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
         * @param {any|null} [encoding] If null is passed the result will be returned as a Buffer otherwise as a string.
         * @return {Promise<any>}
         */
        static __getRequest( url, callback, encoding = undefined ) {
            try {
                return require( 'request' )(
                    {
                        url: url,
                        gzip: true,
                        encoding: encoding,
                        removeRefererHeader: true
                    },
                    ( error, response, result ) => {
                        callback( response.statusCode, error || response.statusMessage, result );
                    }
                );
            }
            catch ( ex ) {
                callback( -1, ex.toString() );
                return null;
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
            return  ENCODED_KEY_HEADER + _discordCrypt.__substituteMessage( rawBuffer, true );
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
                // noinspection JSUnresolvedFunction
                output[ 'fingerprint' ] = global.sha3.sha3_256( msg );

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
            let { clipboard } = require( 'electron' );

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

            /* Loop over each format backwards and try getting the data. */
            for ( let i = mime_type.length - 1; i >= 0; i-- ) {
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
         * @public
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
         * @public
         * @desc Decrypts the specified data as per Up1's spec.
         * @param {Buffer} data The encrypted buffer.
         * @param {string} seed A base64-URL encoded string.
         * @param {Object} sjcl The Stanford Javascript Library object.
         * @return {{header: Object, data: Blob}}
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
         * @public
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

            /* Detect which extension this data type usually has only if the file doesn't have a name. */
            if( clipboard.name.length === 0 ) {
                let extension = require( 'mime-types' ).extension( clipboard.mime_type );

                /* Use the correct extension based on the mime-type only if valid. */
                if( extension && extension.length )
                    file_name += `.${extension}`;
            }

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
                                    // noinspection JSUnresolvedVariable
                                    callback(
                                        null,
                                        `${up1_host}/#${encoded_seed}`,
                                        `/del?ident=${identity}&delkey=${JSON.parse( body ).delkey}`,
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
                                    // noinspection JSUnresolvedVariable
                                    callback(
                                        null,
                                        `${up1_host}/#${encoded_seed}`,
                                        `/del?ident=${identity}&delkey=${JSON.parse( body ).delkey}`,
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
         * @desc Downloads and decrypts a file uploaded with the Up1 spec.
         * @param {string|Buffer} seed The seed used to decrypt the file.
         * @param {string} up1_host The host URL for the Up1 service.
         * @param {Object} sjcl The loaded SJCL library providing AES-256 CCM.
         * @param {function} callback Callback function to receive either the error string or the resulting object.
         * @return {Promise<any>}
         */
        static __up1DecryptDownload( seed, up1_host, sjcl, callback ) {
            /* First extract the ID of the file. */
            let id = sjcl.codec.base64url.fromBits( _discordCrypt.__up1SeedToKey( seed, sjcl ).ident );

            /* Retrieve the file asynchronously. */
            return _discordCrypt.__getRequest(
                `${up1_host}/i/${id}`,
                ( statusCode, errorString, result ) => {
                    /* Ensure no errors occurred. */
                    if( statusCode !== 200 || errorString !== 'OK' ) {
                        /* Build a simple HTTP error message and send it to the callback. */
                        callback( `${statusCode}: ${errorString}` );
                        return;
                    }

                    try {
                        /* Decrypt the buffer and send it to the callback function. */
                        callback( _discordCrypt.__up1DecryptBuffer( result, seed, sjcl ) );
                    }
                    catch( e ) {
                        /* Pass the exception string to the callback. */
                        callback( e.toString() );
                    }
                },
                null
            );
        }

        /**
         * @private
         * @desc Attempts to extract all Up1 links from a given message.
         * @param {string} input The input message.
         * @return {Array<string>} Returns an array of all Up1 URLs in the message.
         */
        static __up1ExtractValidUp1URLs( input ) {
            let result = [];

            /* Sanity check. */
            if( !input || !input.length )
                return result;

            /* Split up the input into chunks by spaces. */
            let parts = input.split( ' ' );

            /* Iterate each chunk. */
            for( let i = 0; i < parts.length; i++ ) {
                try {
                    /* Check if the chunk starts with the host prefix and the URL constructor can parse it. */
                    if( parts[ i ].indexOf( `${UP1_FILE_HOST}/#` ) !== -1 && ( new URL( parts[ i ] ) ) )
                        result.push( parts[ i ] );
                }
                catch( e ) {
                    /* Ignored. */
                }
            }

            /* Return the result. */
            return result;
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

        /**
         * @private
         * @desc Generates a passphrase using the Diceware word list modified by ETF.
         * @see https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
         * @param {number} word_length The number of words to generate.
         * @return {{passphrase: string, entropy: number}} Returns the passphrase and approximate entropy in bits.
         */
        static __generateDicewarePassphrase( word_length ) {
            const MAX_VALUE = 7775,
                ENTROPY_PER_WORD = Math.log2( MAX_VALUE ),
                crypto = require( 'crypto' ),
                WORDLIST = _discordCrypt.__zlibDecompress( DICEWARE_WORD_LIST ).split( '\r' ).join( '' ).split( '\n' );

            let passphrase = '';

            /* Generate each word. */
            for( let i = 0; i < word_length; i++ )
                passphrase += `${WORDLIST[ parseInt( crypto.randomBytes( 4 ).toString( 'hex' ), 16 ) % MAX_VALUE ]} `;

            /* Return the result. */
            return {
                passphrase: passphrase.trim(),
                entropy: ENTROPY_PER_WORD * word_length
            }
        }

        /* ========================================================= */

        /* =================== CRYPTO PRIMITIVES =================== */

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
         * @returns {Buffer} Returns a Buffer() object containing the key of the desired length.
         */
        static __validateKeyIV( key, key_size_bits = 256 ) {
            /* Get the designed hashing algorithm. */
            let keyBytes = key_size_bits / 8;

            /* If the length of the key isn't of the desired size, hash it. */
            if ( key.length !== keyBytes ) {
                let hash;
                /* Get the appropriate hash algorithm for the key size. */
                switch ( keyBytes ) {
                case 8:
                case 16:
                case 20:
                case 24:
                case 32:
                    // noinspection JSUnresolvedFunction
                    hash = global.sha3.sha3_512( key ).slice( 0, keyBytes * 2 );
                    break;
                case 64:
                    // noinspection JSUnresolvedFunction
                    hash = global.sha3.sha3_512( key );
                    break;
                default:
                    throw 'Invalid block size specified for key or iv. Only 64, 128, 160, 192, 256 and 512 bit keys' +
                    ' are supported.';
                }
                /* Hash the key and return it as a buffer. */
                return Buffer.from( hash, 'hex' );
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
            return [ 224, 256, 384, 409, 521, 571, 751 ];
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
                if( private_key.hasOwnProperty( 'computeSecret' ) && typeof private_key.computeSecret === 'function' )
                    return private_key.computeSecret( public_key, in_form, out_form );

                return Buffer.from(
                    global.sidh.computeSecret( private_key.privateKey, Buffer.from( public_key, in_form ) )
                ).toString( out_form );
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
            case 751:
                break;
            default:
                return null;
            }

            /* Create the key object. */
            try {
                if ( size !== 256 && size !== 751 )
                    key = require( 'crypto' ).createECDH( groupName );
                else switch( size )
                {
                case 751:
                    key = global.sidh.generateKeys();
                    break;
                case 256:
                    key = new global.Curve25519();
                    key.generateKeys( undefined, require( 'crypto' ).randomBytes( 32 ) );
                    break;
                default:
                    return null;
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
            one_time_salt
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
                    // noinspection JSUnresolvedFunction
                    _salt = Buffer.from(
                        global.sha3.sha3_256( _salt ).slice( 0, 16 ),
                        'hex'
                    );
            }
            else {
                /* Generate a random salt to derive the key and IV. */
                _salt = crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            // noinspection JSUnresolvedFunction
            _derived = Buffer.from(
                global.sha3.kmac_256(
                    _key,
                    _salt,
                    block_cipher_size + key_size_bits,
                    ENCRYPT_PARAMETER
                ),
                'hex'
            );

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
            block_cipher_size = 128
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
            // noinspection JSUnresolvedFunction
            _derived = Buffer.from(
                global.sha3.kmac_256(
                    _key,
                    _salt,
                    block_cipher_size + key_size_bits,
                    ENCRYPT_PARAMETER
                ),
                'hex'
            );

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
            one_time_salt = undefined
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
                one_time_salt
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
            is_message_hex = undefined
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
                blockSize
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
            one_time_salt = undefined
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
                one_time_salt
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
            is_message_hex = undefined
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
                blockSize
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
            one_time_salt = undefined
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
                    // noinspection JSUnresolvedFunction
                    _salt = Buffer.from(
                        global.sha3.sha3_256( _salt ).slice( 0, 16 ),
                        'hex'
                    );
            }
            else {
                /* Generate a random salt to derive the key and IV. */
                _salt = crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            // noinspection JSUnresolvedFunction
            _derived = Buffer.from(
                global.sha3.kmac_256(
                    _key,
                    _salt,
                    block_cipher_size + key_size_bits,
                    ENCRYPT_PARAMETER
                ),
                'hex'
            );

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
            additional_data = undefined
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
            // noinspection JSUnresolvedFunction
            _derived = Buffer.from(
                global.sha3.kmac_256(
                    _key,
                    _salt,
                    block_cipher_size + key_size_bits,
                    ENCRYPT_PARAMETER
                ),
                'hex'
            );

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
            one_time_salt = undefined
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
                one_time_salt
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
            is_message_hex = undefined
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
                blockSize
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
            one_time_salt = undefined
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
                one_time_salt
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
            is_message_hex = undefined
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
                blockSize
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
            one_time_salt = undefined
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
                one_time_salt
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
            is_message_hex = undefined
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
                blockSize
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


/*@end @*/
