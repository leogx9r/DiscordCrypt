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
 * @property {string} canonical_name The canonical name describing the exchange algorithm.
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
     * @desc Proxy to the original file system module that doesn't read ASARs.
     * @type {module:fs}
     * @private
     */
    let _original_fs = require( 'original-fs' );

    /**
     * @private
     * @desc Mime-Types module for resolving file types.
     * @type {function}
     */
    let _mime_types = require( 'mime-types' );

    /**
     * @private
     * @desc Form module for manipulating form objects.
     * @type {FormData}
     */
    let _form_data = require( 'form-data' );

    /**
     * @private
     * @desc Main electron module to handle the application.
     * @type {Electron}
     */
    let _electron = require( 'electron' );

    /**
     * @private
     * @desc Process module for receiving information on the current process.
     * @type {NodeJS.Process}
     */
    let _process = require( 'process' );

    /**
     * @private
     * @desc Main crypto module for various methods.
     * @type {module:crypto}
     */
    let _crypto = require( 'crypto' );

    /**
     * @private
     * @desc Path module for resolving paths on the disk.
     * @type {module:path}
     */
    let _path = require( 'path' );

    /**
     * @private
     * @desc ZLib module for compression and decompression of data.
     * @type {module:zlib}
     */
    let _zlib = require( 'zlib' );

    /**
     * @private
     * @desc File system module for access to the disk.
     * @type {module:fs}
     */
    let _fs = require( 'fs' );

    /**
     * @desc VM module for executing Javascript code and manipulating contexts.
     * @type {module:vm}
     * @private
     */
    let _vm = require( 'vm' );

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
        `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`;

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
        'currify.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"eNqdU99v2yAQ/leINaWgEit5DaXRtHZPW/uyPllW69g4YSLgYdwscvjfB8E/2i6T2r3A+Xx3fHffd5OykbnhSkKJWl7CSK1/stxElJpDxVQJ2O9KaVNPp1EjC1ZyyYpo0v/cqaIRDIUr7kKphIgwUTPg6/X1x4qhynQa7jjbFSiYMEmxDKmtYAYwAhk99+yey0LtV+FanovYCLXOxCpcZyNqJsqVP5Zmy2sU543WvDx48NbCYSqo1cw0WoLeAyRkWGOD2sGjYImb0/QmOinTYLGT9ZxpkNMzQ9DsV8O1m0JnEJ/TTKc56t7LXdHJHHk/73288/mqgkq2B7daKw2fvmRSKgNci0XHCbj41Jb24gkRs9VqD0Scq8JN8/v9zcO328e7+x+PX+8f7m4iLKwvV1EPnbYdh8vWWuJbSOZpnGdCwKqnF79UjE/V9BS4SBOZkg6pgvp4lMjiCo+JEofJ2S7Iv9j/PIHg75pU6Tr28pB0TuSViQWTG7Ml8vISKWgcCDSgsLDteF0mI2wPA7VR4xRaG82d2sko3pc8O47dW6HHTG+aHZOm7t7Dhn7WOjtAfb1Y6dliOUdY0QVRV5ooB8UkarZIx7REpZ7Lt+s29DsIU6LAWKA2KiWot6oRBVizQYSTCFkHD/fNX1PWWb1U3F5VlTjAZ8ULMHdDJ2HAfwtbvo5MmCNcyTwz0OBTh3GllVEeXVwLnrOgh6ExhBzN5QBg1mOaLcib1fE9B9dIBvsXjrG+HRV3Iu5j8X5TP5qB1f/kYP6OrNS6dXa6Px65tbh13+7ASdTJNEoRHGxkEfkDtSkDpA=="},
            'curve25519.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'openpgp.js': {"requiresNode":true,"requiresBrowser":true,"minify":true,"code":"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"},
            'scrypt.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sha3.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sidh.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"eNrtvQtX28iyKPxXHNb+vKRjQSS/baJhyYRnQnhDICfJkm3ZFtgSkWTAibm//Vb1W7IMmT1zzt77u2TNGPWrurq6uqq6uqQejsOuO16L/f7IHkyDXuKHgab/unejgmNM7fvQ7xfMN7Y93Zi2fz0Zkf3raX0QRppT8IPCVJ+ujdz48CE4isI7L0pmmqMXi1r0xflqT+FHX5+uudFwOvGCJLa/fDWma8nIj6H2MHIn9sraW0yu3dH0ChT/mPqJRMQxPP1XMorCh4L3BKV3kXcyDQDQOiLoGYkR2JAbxgnNNnz7jbUe2Cth98brJSu2nczuvHBQePCDfvhgePYKhy3L/MldGCWnvci/S2KAsNAY0Ot5cVws5jSOPMA48orFNwH8DxjZ5MHHBEEyNAaGa6+srPsbmmt//973o8CdeKWVtzjcyHP76nAjSnpvPfKSaRRonv0DSKrP51qI/9vevTvWVlinK7q2MohXdN0YQOFgsfDOTUZY7NiDtSCMJu7Y/+kBPKBDSLre9sfe6SzoYR9GtOG1vbUkPE0iPxhq+hPDr+MHbjRTsGQ42rQYsH5j6gzhgrfWnQ4GXgQIeXbgPRTO/SBpOlHkzjQPOulqvAZg8WRY7xhxkU3u18ZeMExGwEFpPlHrfLG+Qrd3Y7fnaW//+7/fDg2gJABWGS0FMx77ULWsGyvToO8N/MDrr7zh0zcJ+9MxzJ5GH9a8R+SF2J7qBgcCI4aWPXc6HCVbjz3vjjCAoZLDH2hvyIqIEzfoIdweEJTyrfOUBTVyg/7Y6594yGUZWMjvvLb36CeapT/pi8siU8khcwXd3wFEdRnTSVn5sjWJCXt7QeGADLRAefzrypPeTja0PNLg3JKZyPAon31kTDHrGzswu23KDhTj5zgnw93Ad7kry+1TTtnI8JEswdZtratllyxAZqy50iU4AIcAvwGZ8kZKaeNEw3hD5SKZ3RZiUJQSysi64gnYbHEoOHukwcI0YgahGAwjmM89lJ7BRj/sEWhrvWkUwV8qm6DItfOL1uKop7ddO/bGg7Vx2HMR/too8lD2ELyBO/re4+FAW+mCxG+v6BvuWjztxkmkmYa7NnbjZI/XgPVUsvT2So6AAmkczRgD4Kx8Pvi4myR3JyBzvDiRQgC0AfD6ztbZigHiwQLar8Ve0NeC6XiMiciL78Ig9s68x+QJ0O2NgH8I3IgyFiypSGfgduBxnWuBJ8MTXJnDX/80egIjmDJ7xUVGozy2ksY9K9NEQ/3FcURyEHyFODFI35S+4yogyRtAksHc1I3kOcyhfjAO1RkkwqpsmsCbayCtkmk8nyuJYlHC0z1NSax749gjmAV0ZMGGpwVclrcj0BdPpD8visLIjuBZUg3FU+wll0QLn/nJ2EtNmmDqhBSByCSqM0bdDrooAWWSt257gFg49jbYX2D84Ros977GMoCFc1oRiBvkt02ntMf72YqiJV3x4g3+0H4GoWKRY/TgRkEapfk81qUBBayRa0Ch7WRHxIDidCqMqXbgPEwUrFXXjQNQ8ms9z4fyt57+X95TxKw2wqqUS01K0D5aRwJglwJ05vO+o604cQz9Y/7ABaug3y6slICn84aJi/a91wv7XlQsYidKBlAvGTRX8rXtiw1XrfoYLBeC7MwYGRPjzvhuDI1748HoGLfGnl2v1Sp14wRG3mg0ylbd2BKPcmSbKVKZ75z/D2WGU7K9VXgEe+hJVD2AFTFd291yjpr2iCy5PbG2Z7hKsciq8xKrnimqlO07XlgpZwrPm/YkawTJQgYVyxbAngNcXrgAdpsVbsPSzimtV2VpvcpL5ZBPuX0PbD+NwdS7dOPJxl77BMzCslVtVJuVerW56qDsuvvS+eOP8tc/PCbDgH+ocNslTLxrE+6buI/arrGlr+++Yw3W9V17950Nc9VsmC2rvLGplf9r13D0Nm3gB9qmplX+a7cke9TfVg20Ten0U9MeZOQY9FmHavtdYXCAjQ0La5Z4H4nFaNu7GxpITCABFUj2zE4MmFsUkW1AM0Ip//Td7timkYEKCymTk2OwcLUS2aN1qloIXTvcCjHSnOPpKO5A8jOd4HBmfGM9sYc3iaOhuvdA2CF07dbeZt3ifigJcc2s9QAtKkAOiYWzNvQSRVq896iRgvJE4iPbg/kjaLSiY2Nd17LYV3UFzdvU4Bm1HYXUT09Ih2OYm7PDM+fj99MzZ/PDfF4rV8vNpmnsioKDrYPDk6v5fHF53iBoZJ91WJrM5l/nZqWzFo/8QaIR1SltKSFDhHr11rBwfSWYTrqg66TduEHFn21DFbDLwKbrz4JNIOT3e5iRtpL0tcggdVB/ZVqhamjTwidUfQUPNdzuu2OQ7tqKOsRCPAqn436h6xXGUN0D3gUTv6CQxyg8uDHI093SypuCphTYK6Xj0oq+ogvG3ZjZ/LGtzRY4bVdXWFxHDieL5Qz3vu/x5xJ/DvHnIiXst6lIHBG+xMcnshDdbiwVCH0ajMMwMvgyJeCvYNVc20gRY5/8WSdbcbQsvP7exB16sf2L7c9ppjPt+yFmkvbntO2RvdJ3E7ft3t3BnozYqG/DXuIlq2CGeu5kvevGXr1qrEi0PyhcSPelyuIAkwX2apd+MtpwlIR2pLdxHh1h8x7phGkf7S9pO0hM+RSXxgnsy8LJhTueejpf784yV8IG/dNGi9uIpJ/EWetFM1iQG/yh7axN4k3yaHgLLpYFIW8JERdlcIpRzDhfzK9//PGH+bQO7Ghk0bY9uZD5CJJFtwBFDJguWMQHLD4CrwMLPgbRwLdq2PG7d+Xq3IEN+Lt3Vh0eyvDQhL+VrzrFKcjDKVBwQvN35VNYiD3YvngF2lWBruDC0APb0QVZVhiEYDysPIFBubCXLWThw6r8uv7drpcrZeP92t00HgES57/JaY749/7tX/kXleqhdzTaH11342qle9B6PHAntc9uf3oTWRPv6mw42rto7Pc6Hy/80WW3N73zBredvcPdo37H8i7unf/wf/Hhf/r435f+yvx/blknzcHm2aZfuX4sla8as575yZ9ajf77z1Gv+RCcbB5Hk9Pa5k60vRmXq/3T5tu90/Pe4WH9/Y/4fvCvH3/n6vhDuX+ydfWwN7vbHv+4HjnHu92b+8pNb3R6/mlc3anVP2zuHVU/trZ3ds9qm+HP9/v7w8HPYHfUGvQem1c3w7POcMs6CuPz3SQ2m4c7M+t2/3HQq9yf754f/5jt3P34eGj9vLiN7w5GW5NO73bn00nzaFi3Ov82jHyMP1v4s0nSQ/zZIwxCqJSpRNPn+LNN0qR+TzSiQG7xZ5+kj5emD0j6AX8fRPo9Ka/iz1Gm0+PcNP52SO4pSQ9F+kKW74k0Rfpcpo8zadKe4HeNPzukPMTHLv7skvYE3z5Jk/rNNOWylFTTCG+T4Dci6Yc0UWg5Sd9kiJZNj0kaoW5e4WOAPx9IOQH1Q5aT+SGD+EDghyL9cSjSkUwT+k9FmnCCOkkk/UjSxyJt4c8nUp/UMkmalBP8KvhzSNoT/OokjVDfx/hIiHhE2pP+3y6f9Nw0yTjGjK2tTBpnofM+N439beH8d3ZkGvHvkFk7IfUR/w5hnZOhSO9KpusJJqNppGeHTMXpg2BKWj4U5R8zTKvUj/PgfZTlSNrOJ0yfPQimJqQ4Hy4XeJJgWa48WL7ej39nvSusvny9f3CWslLu+qes8vA76z+bJqDOMuv9Uq7vq99O78hBU3lA8IkFEag8MGX6WMgHpbyaSWfkhyoPpHzwpXw4l+v9WKQncn1n01eZdE+s7/zyOE8+RFJIm1IeEHyactLI+t6S8kCu/1lu+bEof5TygbDOz0x7mn4QTEHkxyeS7mWYZJhJh0K+HBH4BP8WSZP2zYx82cqTH5tSHijlQyE/NpeneyJ9epwuP3kQ6f1M+12ZvhVK7ETKl10J71a0V+QFGfoZaV/NW7kE1DnmbpP+zqTSI/KP8PsFtt++yqR7Ik0XyVVe/SuZHi4tz29P5JlLykmaLDIyyZ8dUU7Wy+fjdPoK0ztkfkZ5afLvaLI1rH740OtVku3du03rY9M6rBxUf7a885+zyWbp09WPgTO77h5c3DzO9jdvKvXw8uONVfcvrcd4fO4M/6KNtf1p/2Rr9PDp5/kjN76J5ARcGw8wF0d/xRIv3Td+jKqlrcn2ePrzph//rGw9/uiO+3fl+uH95XVtdLi5Nfocjx+2kssP29fJrD6ulY6BIL2WuXtRu2w6r//+1f+2/t8e/u7x37Mf+hugeA8wF4e4Jt5HN+GP3cA6CWdntelj5eFt2N2+/nFZ3r2f1FqjKciU3ePxzLw4/mBdh48/rEbp+Pau2us87lon/bfDq7+6P787KH08aJ1fvT9tXcbV8sPeiX99c1u5MhMzOrm6uPrZHOy4J5ubH+7ck/tu78L5WJ/VmqXD4c2D412Ejf29aNTvHk+m3UP//dGP8m3ytvx+u7xX7Xwa1w+6u6edqFH2z0r+UXPSPLlvlm+uHzfrZ6O6E+6VoP+L4+7h271P3eHWjWP6nzs/62H1yNlLuoeln9HkImq1yhMv2m3Fe83PpfcfKz8Ho+Ojm4twNnTKF9ZV1e3dlN6ed0onu6FZ+fGpOeq/Dy/dYbVTvj18OOgdVobWyLq827r4PE0uby7Gg+7ssDy4bXy66TYbrzIBrKBe0Ns/PUr6ycFk9/LxslLavW641evp9dnHKOhunyTu7Y/xXdWsdCq+P3x4P9n9GNzEm5dX1xWzlmx+erufNO9+Tqyrh5tS9/bzzY/yTXWnc3LuV0on3na/N7Wu6x9/XpQ+7O239kqRc/zjsvHQvR92zHs0Kr0df7h/t797202c6X3XmsZu4+7mZ+ljZ+8uObm8mRwOnbPK+enAG2+Pzd298DApV6Y/flbKPx/Gzo/ux1I8LZfr7qE39Tr7D6ePxx9vkuTk5PDkw+nlwaf+48nPZGTtb21f/LAm952TZjN0PwxHyd1mr/M6/e9Pro73mP1w6dQu3p/2atNx9WSzZO4fWJ142ug6/f7Mejxp+R2vUrJ2O9XR5Efr9O3d7ej0vPuj73362X8/2Dw8nIXeYPxhtD+YVncHR63RwfXkrnvVL0WRteNenTnJh4uPnX4nuvBHO93BtHbq3Y6co93BRccqncT/elJsj5zo2to6uXFuPtxeXt5NtjpOf3r41vs0294/Ln8edoMw3Bu+Hd6b51f9o9sPNwcHt5PO28Oet2u1fu4++oedgx3n7LzkPx575Z9nD9Xux8vjYLv102sd9082oz13EsaNz58uT2e3s63Tq+3Z8ZW1+1B6H53/O+jmv4LD5sNfsg9P/QOy5/xX/vtg7f8FG/x4WL6OP78f3Man/Qtz8+ToqFH63C/fTs/GsziOvP5s+/qu09qrJR9ODuq93mn/cnbaenzv17oPt5cz818//Zv7jb3d/XF/92LW9TufuuUTq7tzPr0uX5jnk+3p9U4ruZhsx/3L8/DDWTwcnO453qxzd+074dll67Z/+Tj+OOmP+9v7o+4EbIWL61F392K8995sHZ12LMgbX0/G0+vL47u93XjY392vkb+T7dnebv8O2/St5vDo1Am65f0f15efzP2Z0zo6M6Hu+OH6sjUR9WbOW+W5vrf7adzduQL8r0c9v3PTC8YP/Z3WAPpebGs1p1eV/Vpv9+R+b3Orhf31L2u315fXUH5xu6/CVuu+D4f98hjpUPk8qyU989PM+9wxuz/5GNLj7lmfzCuAe/V5/xbxuA4uANbJXbdcDT+cdjiufv/yCsbcmV5/7g0vLsfT/vuD2fHn/dnV59vw4PS2sbfD+gFcFufi4ueHnX3r2r9V5w5gwjZz2xwe3VRLe+8dKDMbz+H3YRPab1n317sX8fVpLbj+fHKKZd2ydXl1+Whdnzqt59ofzoCzdz6N+jufwr3N0ZiO72TmyXGyOcH57cyuP29b7uf98YfNPs8PkKfy6Hg2ad1en9+d/QYN+bx39ysMxvl+rb9z8XPfMsNPmyqNnPAquJhc/uz0994/NPfe75l7uw9DmrfN8rbKMm+f5Q2Hg01GX8u823tfLR35zgOOH/6fpWh2Xru/3rn4cD4b3kHZc+uJ0CS37U9cZ52bq88nN+6mE16f3g5hzZnu7j7yfXA2aQ575YubPtBS0A14qX9p+def94bQF/DVPsxLa7a3c32PfL5PYcJ8msPBsW2vkFCCn/b39Y79vWRbdePBHmv3tjaEP98hq1qyasVVq67rpWPdYIFI9gNp9jEVDLHDA1BoyMmXr0Zkm+uRDEaJSiUehel8ib6ul2u1dxh/+7FY7GpvLGNlc+RGbi/xogIGrxVWSklppaCtlFiMwiAKJ1hlEwq1RC+t6IWCmxTCwSD2EqgdQe0gTDAE0Hw0zVXzcXt7bUU3kqINXWE4KjnIzoemP4k41pvQD7SVFRre8Cnv5QY3Cbsb+NNeCGoyInx/wvCN0JjaK05n8/3W9s7u3v6HjwefDo+OT07Pzi8uP19du91e3xsMR/7N7XgShHc/ojiZ3j88zn6aVrlSrdUbzVbprb1CXnMwBkBJEt9oOzJO/8s3Z/XaXf1prrb+u/Tfb//b/opx+yv6Or5EwKM0nLUeDNJJtAFQX3/3rjzXgqXF+h9/VGHWNJjyAOpW55r/XN2ykdhapehD1Tq+R7G0quGW7Dyye7pRr76xbR+jsPOrRDqrEy6vk+DLGkrQEw/2cJ8kd/5grxRg7AsPHc68bbDSDcOx56ovsRRhcEqwmmezWDDsnsTBk4iHFR7qFem/aBwbD2FTavAYu2ykM407AubEaLBDwsssQUPD9Cfsma+ryP6EEStJNgAyYoPH8BNzPXjH0+ulUqAnX4KvdkSmBOkF0xIIGiUSdRpHjYC3MNpYW9kMg3sMXw2GBTqMQkyoX0jCAiIYs6hWWGRPTzDn9KWQI46K/jRdc+PJDnkZyomG9i+MfyKxioaI6muLJ0NGgrbloyFDQNvy0ZBDb8tHQ4n6bCvPhhIL1FaeDTXWs60mDDXOs60mjE/upzb8D3gN/MBPZm3rrWnI6WrfYsgWDPuj343caEbG7XbDKGn3HcMl8cDtruEFJKrtwJuE0ax9agy95CxM3DHNkIE5u08GaXwYbLoBCLcdmCJRByOMaXaBwStMSFmBxKvHa4UtPxmBONUsHUTq5A4mq/AAWYXCalxQo+3szwVa8Lkw8ocjHm0HjQvslYjCPcYF0XA7o6CVcwA6Hz8eXjKA33dODi/Pdm0L4I783qiAkaAPMcjmXuS5MWEiAB77Pz2U4dE0SPyJV+hOk8Jd5N3jSx+FOISc8A4K/J8k2iiGjit6AaU9feEmFRSJXOly9Cm2XQ/WjUd6Ym/DYU8AJgSaVPWCPyjMwmnhwYXxTUisKgJhpP90/vFjQTN18gaS5/ZB0RTw/akCmRAjZ/ydw5OzvU873w+QEpu2WYB1YfjBfXjrffd9P/0igu9oNEZVhGDxCEpZVQZ5gXgKHBB0Bo/MFKGbTrG4Mg6D4c3kbgVD5fgbUuvk5YCzUeQ9aJZh4osE379/hyxY3J9CJQJwugb5XhQF4Xf+kguI2rsvOfmaTrQ/hswBNE+8//Qd+P07BuMn330F8uMX5yu+8abWBAbt3c2+d/0hJwerPCFBlBN8f8alotHwSpFu0M7eX31yDvY2zw6Pvh+dnbQ7RuJN7t6H0+7YO0qi9k+DRH5CcXtIH2ESPrfvaaTkZ+MfhuMYEXToLHktxFmTciggwhUDjQ2fFnA5EtokztfHIlLAxIUOuh4LQixwoY0ikwakxMWSmJVwcD0KLqbgFMGkG2Na1KNFqmjSjRktGytlTDjpRpeWzWiZokWMvm3OvbU0HY2RDRooRUoDa3Fi6sYEKwiCAhsZdzZIehSASAAqAjH7O2Yroa4sgaGw7DH+AauGPd+FD/yxF8oafsAfE1c8ukoNV6niqnXgucwT3uMdfxyHQ9EPxuKyZ38yHevGUKA8kVAn7qNoMf5ZKWMoM6533bhHUlABDpkpAa4bHdtbS8twMKRZ00XZbdwiLCkZAJ6yNnVjD5ouWV7GSaZMLihp7GzhInTmYAkwm9Q2wWQw0TYAljaBj018hQ3NSmBKExjRBI4zgbNAlcH/wCsw8ybMtQkTawKlTBi+CaM015Fl7JFesupzc70fomRyMFD1XblaI3JqZtO0ZW1Y9bZTsqziatPQoI/59ItVLbdIYKs2g5+KXqzMTfEmF6nRLIGVW2vU6iVN6ykVrW+WXmKJd+8ssGR1aIryyNDMuZaQxlGpiTm6btuQ6egbrEe7V/w/GrRZClFva9MvSckqUwFnTL84FJSd4OQ+g0nFwG6rpG5l3iGpDktbcyUFi82D1QUoYhC+Nmb0qFg00PcdAjQJBZXOJHV8Up8RJrA1MM01DUilVIbxMRS1sniem6tKCv4VzVVHX7UI8f5AEKkMq1zEzR481YrNeW7p3MeGPq2CueViFXcV2Wwtpx6BbBXL8wDLApqgeUjUbK6WVw2JwjiAzpHh4GwDLZBCvsIClFqBZJcNLcMQgW6IJ8IDDueBdFuDkz5I9Qyc0sMyXzDAjKRmLI3VK/rqbG6RbJpMlQBHjEHdJpwbqjgap4i8OiYztiGnnWSk+m+L8Thz2cRYrA5jBwy0yM6DxNaRnRjK+DGRiFEqi2MRAoImjCxHxcZiAykY3/uU70M+UPMr9RbEJKNulk3ga0BQ00JguVDl0HRGlkNzSucRNowyHBrb2Wwtp57g0BjL4iyHZnO1vGq4z6aiKba11WYRKD+wIzvWKVsgQ5jrjF8jkKQkcz4XOWWT5KzrAxuXucuBRGB6KSCo3IiJ3Nhw2gPozd9w2zHSeUDKoOmgxGuCbCHwB6VylS0bmqQTy4Q5kZtEfA50/hI+qQe9Q0uTMYteLKYKUB3QArDoQE10wcy/fSLvI63rAIUyOEgJR4HhAJdFdkDfgiVdKdUUiATYOqv9BBQijGhCyqGvEUVsJFQcEKIuSvKI1IftyNjDdzfpcIExySg5LcpNrlIGlAqcNx0+p5wqCwV2BEWMt+2QShVHZ5SgeLKGmkYlFZt5Ru0Nn4y57UsKIUg6eMIWVKj4hhB2Aw6CvN7KWYmNmlUHS1Cpz1iL1aepbP0nSSSmfGKq0esbWseOkaEMhKUqPSgYoKbjiKPqI75CIlUHKfnoCvUYk1RMUnGuKJRSrdj7TVEom8x7/zpRGAsZ6OpMBAJ/Pj1JTqBmkg04V1v1RrlicfOJmUxBSlSCsQr5dCk3N9j7fzVqNWxUrDY+aI0SCBqruqpptbJptcqYVNsBZTTLrDYrRNoqBTqTnnWQg/IZhOZLteca2H2NOlQYIPBBiXYsQSjggMBLa2H2n4GEf2uYAf8VrTk0sdomk2h0XQ74ulx32sxO1VEegYoBJUQEKBjBM+irYvEVaLbLtVUiOy3CJ8CLIL6IWPSZEHYWBHAkDLc3PhF+0Aw2jmBB12t09RecpxAyItt/oqKQ9KdNCLYOX5P6HDInVBqw9YpSsKS5yGCWlD8bSXtivEET3w6xF4vJGPfdO9viAhEgJHyYWEeuaUChTkc8obKMopOAZcjMZibh0LwE03GANqSjFwMui2DfqjksD5SvTOhEDaNXGNDXpVonNmpP6G6mukXGHIzhxSr5rXSuznHVkaWHOpupbCBtNlvLqadLdZ5gaZJV20/JhsZnEOTXAB5dlItIuRqnHNNtSCpCbRgE5ZBkCYdsjNsRehRg+nyDTXCyoP0Tzg5khgcg7aFrNsEJ6C+crzeUXYtFl2p5TW4lRKfFIjMB4pQJEP7vmADOchPAzzEB/EUTwF9uAvjSBKDc3smo/06e+u9kVX/I5u4FxR8tU/yiwHYUxR9QxQ9aNyja7HG5DRBmbYCQ2gChYgM40gYQSjpEnR7l2AAOtwEiQzEZHN2QAzXV2swCyNRWLAAuPF1mAugd2/1zFoCY26wdEAs7wEWZgRkuyXCRWSsG7bJcqyM/MU6jDgTcHyWKOZA8tytKjHSljAGQLCj/WFX+MUFUKv84rfx5azbFxJJkUo+IQZfoS6mvXa6vXaavk7S+dlD3QedU7S7TyjkVpCIGKbEMCOb/mZ4yyjvBJiCgSEfLlXFClLFOaU1IVm4KQypGlVZlBjxNssQbLSjCrOCM6eqCmiNzOspkcDZVZ0OdpphNBtOhlAcZG6eUOKBLRKmr071oYLvSHEi4OZBwc2CdLiEkMNHLgdDLjHOYqUC6iEQXNu/C4YK84D0FqKtB/EYgy5I/PzawKOQSpeJPuwe0OA+rQhCb3y8A6qg9OGrf5qL9r9qvRIjN7NW0RTGjxqy03plbi7uvQHITUyRSrHtYDsQGxl1FxGQKNZk7wox2yEi4nHCImEoEztLxNtPpqsc2Eo6ZqpPQ1innHFfWae8cHY3mc2TL6cEMbX9VoAughugc7vDKta+6HEztq32P9BedDpUBoRik/Xa4d2RWqsIcGhqobS7xatXG1w321KLCDR/sqtmqGyTRVBI1WDKrFn205CNbblDZFE8NLK4XvW9ItnoNFnXTQDg6LHUXMWmwJQ0WEBh48ETNGXumEgMHgIPX5511sqEWeFdaRM0IX2et0viKLpTiQOeWEbHXzPmc7oW0capUz+uC66NqkY0GTAi0cGEMVNEkch7Eqk/o+o7ADq5X199wjIgRwRBJqNGEKFAnDOULhsofpFhfT5lDwtv8C7ovN8XajqiZpsWrPgyGKjH+QZ6GTg0sAuLOoXWQsigmNInUAhak51XrDbfQXZs0NaidalXlVsOhJXShBlCcsKpQrVInRILlyEwngnnWMoIsbuXKTokBARgjrkCnvk32DVqfM2kTjE+rGKGX1Wxr/dKqVYpgd9DXVzGPTyyeL3BeMOgy6xPK97N0oluTuWQeyk39UlcwT5cwz5jyjixQzc80tc15X2eHAxGhYR/oF2XoR0nWp+R6EuTK0qhSV/dQQJzVZI5KjHDKu5AMKskMqshoGeh8Pm2WVFB2QU/6dpDBCr8wJ+C8I6bFalKSMgKpg7swSoClMFiPhBYOYkGe8LRQ6d8p4VAW20sacElSnbMnugKfUjoBMhiJYN7ixaWA+weGjzZky4Ethrn1TftuayCDTD7bmnYnGHB1yKd6PiSFd4TcjLpDnT/d6d8snXzi8fvGHTZqOzCsIR2WbsCPmEOH2vxMSLkog1nKpkT9g5c3v7INlsaSaF7HitThIiqmUsehUocZB+hwxHUTSeMELSu23VeWO+BYq0ouBuuI1Wmmd0QBlkJVSWo0BMAMN3B9UmuHqnkEWyxSX55PhhDRdURdyL+4mZCUXDzzkrqPkOOeuC3AfCg26BqHnT+k9GJDaLq4dC90Ymf1nhgVXPNBmpyCxOJ0rMpUZB0/a0y0lbJl9OmcMxwqKskxafvonPEJYln6cqoyK45Qsl5WKRnlUzIilKyXBSXzCPiL26I+biLGlNTsTAehjumMuni6PwYMiZRsFMlzk+pTQrtxsYHPxFIYEG8NrZqkCJwQAmPF1TEzOcbSeJBWrTmP+Zmnnp66gWKndMRM9eCpJ2ySjtiiacI6E+B+SXiWCs8S8KoL8EiKhop2JOFxqVdwMS7wepTaZJIdn9ias2lSTnn5dCiSnG/42F922uvSM0+GgXIsoHp0uXMl5N446hmJUl1Jz0ikq06ySLrp6HDY3gB4QnFpyFoLJyQJc3MofpKAO0AixU8SgTBOUn4SpdqCn4TVFnuLlJ/EWfST0O3/gp8E+wkZSE56upWT9ODekES4SVT6wJwtVFAPNegWj/2ls5aw+SpET8+4SpxcVwmHDG3VQSi+DeI4SdLzkT48obwhD0/eKNXZJKtnMmZOI8V7AtOL+0FXJwqVPuIaYr4ge0DxI3tKIUhWy0U2c6ll5VMvSa/kUwFEvST+v8hL0lO9JHT9Sy9J71kviUNiBZo8fIRwivCQ+FQZBXaF+7VZaEEDdtx/u7Mk+B9zlgTYJHjRWYIBBdxUN1Ncyx1JgXCk9LgjJaAklo6UN+TonGbSLF2cHeGRGg1wkE6ViGyGHWXuFMdDL29WezlOleg5p4ovnCq+dKoE3KkS/B1OFT/lVIlynCp/amz4Denfdar0hFNFBdRRe3DUvpc6Vcal5pNiJb5JW4aKfcYtN+Is0TIqlO1OHVXAkzcGQjzt6pRWqw1qXtBH1cRgOczMYGcGXKX8YW7E7RBI6kItk1iBYNIMbWbUDDNGzZAASXk+qOXhrA4VLwikWESMs9QWNFDi08JygyQoicl+gxU3WQWSV+Z5Sr0Kz2NTQjKrXw0GhNhwpKntGqyMO0fAxoSGMHLQL6jNgRdAvN6TCAwuAhuGds+4A6jWwd91snRhekK6CmKqB+VgiGxnCcUHHq7GhCQhTxkaZjHQRLonPCxOFMgjbSNaFP1qRX1DHC9R5Z8QvLPxQ2oLPKJKqLw3+HnL73nGkxxneGBL2MrxtTJIdIrLZI60T4FIn2TL/N84yM6trGgEKrdfOMdeVks9x/4dSDnaINd1HtCEmZH38T8h7/9HnOiUqFziQ+p/Rubzbv5zXOlEtbMDf+EiruBpvy+lRnpj+6J0qqLTgblwabrBPb3VKjO6aMJSE1VM1Ks0UVETdUw0yjRRUxNNTDRpr+gwFgn0M0OiSUtaSqJGMKDu6GrNUhOIQdOkndYqagIxaFq001pNTSAGzTLrtKEk6iZJsE5bSqKOGDQrtNO6pSYIBlXaab2iJggGNdppvaYmCAZ11mlDSTQIBnXWaUtJNAgGDdppw1ITBIMm7bRRURMEgxbttFFTE4hBy2SdNpRE0yQJ1mlLSTQRg5ZFO21aagIxaJVpp82KmkAMWhXaabOmJggGTEs3G0qiRTCosk5bSqJFMGDM17LUBMGAMV+roiYIBoz5WjU1QTBgzNdqyETNJBgw5mu1ZKJmEgzYwYhpqQnAoG5S5quZFZbo/FUzp5MyczrCzFnu8so5RBOKfPHYyfn7j534i4nkAL9ettgeHVafcuoi7znY5e/N4OsFhsffMUiy7xbgcEZ4HDjSS/UaboBw+1uxqOWKQj+Ctrpiv9agKS/njhqk8qOWlAAAQjCNSrOq05wyWqhqDqr3TJ0GrQLal2ZAiczgwU5z+uApp02JUadHWY6DL6Au5hPnywGQAgwvXVTYcyDHx6PEBGgbYNUth42nVmdmV71SJyYVlLTqpVQpjpZWKLXQ/DZYR5cab2ZgjzCwFhnIM12jGn7gfddN1jcjI55N1HRjmxU31eISNVUQPVGfP+jGQzqXzgEDN3TEtOTBhgIO+z4Fhc1bJBuVuYlKJlDmV8osn8wjx5FMsqhL8ug8i3o/Ukiz+gQXI8F+f0h+WlrOsFzevsX6TOHDccBaETFSAhFRGPAzZqtZI0dkZKkTN+CZCtAitiSA+S+HiiCDF3McMlU4mUl0WaPcVEOUA3y7oIRBejMnhXUWfYo289U2oC/NXw2Eiw+sVNgfBCAuA75F8eXuJ3G0pRCTUoPyPy49aiya6x81dQwBGaasSddbgFjrOjv/pB19VCeW1f6oTqaSJyaQ5Z2l+sQ360vkHQLeOcU/W0/S11DnQDdgEm12ShpRTJmTMOBxfumZ4GL3t2j1V8bZ54tNoi2WIlt9fAw32SUvm7D1f5NaKSocvvBvVBQkcLHOdcNTVr/HkxSmxzEhmQyMx5fxnkIqInPIizl7CrhsriKfZC4Dm8m1iJPOWK2UiyFv3lBaWyyzonbPMwmpDcv8L43KQsQWJTEuH33uPqXvUPqz2tOr/J7y1HK0Jy0jytCsZlQoWLlZFVpuZFQonTyhQk3YRv6d6tP6XfUpVVjTXFSftJStW6iwqD5pMwN7hES1/GfUp1DdjIRhnnqDorTqpHX5A1edPJfRPmRqkyZz4GJBWm0KCHSu8tQmq59VmwwzoTQktli2VD2VK6089URpCHjAEl/UTlAqF75aQ1VOFVQrebpp7Kg9iAeucl0eEVJPa6XlGilIAWRw0jpo6uSOKmCjWq6E0g35dGfAsfnN5JIppBQTHeZoIlI/Uy2tiAS5dQOm63lFlKa6+C5JPoX++uD6nGslPwieZtVS+kddN3KArOMbKbaycBgSN1KMqcAVhDxlGXH9w2Bm9A8Fk9E/dHyhomWYVFA0DFvcSg4FpeYQJVQ1/ysUoCmioVAr7DFXkRwsKBIjktpEfcdbeb+biDWuVloERbsKRolvJyTqUMe3Ek386I9fquLBrc9ci7r+jni013V+puCjaxjbvNhAvF8iVEWOSnjDRRg7X11a3ny+vFJeVu6ziL2q+TyEWvmF8vrz5fUX4NdfGEHjhf4bS/q33nkkGM5k7y5wHZKpidPH/cCmIXy47LmpPDN3JkvUlYRwQivvI7CECqCiAqioAKoqgKoEgFxID3wMb0OLHa1cbdUNypsg9ol9I+ZRPfqqYfxVBT+a4ZcqFs9rowr3ecMea1ippxtOcKVpPaWdEROVKLpNl9kN7EfJg9XWw+tOEzTB/FKDnZ8QM46q0laLhv3jC7gtqFVWgpHI6jHnp84Xi/i6m2RcX7XQINF56coB0EsLQTtAD+ZXOy7iOyOpPNiI0GMnR+uBtcMGMWagZISfi6qBy/4yZZqQvB4vJoHPSCk9QaVMqcInNF1PpxVuoekMuHIGXiUDr5KBV83Ay+Mfy+ihQcdG78D40fxSyGF0MTnm1MIbZBdaELnrodz19Ha5LEhEbURfb5tSHB/zW1+ZCP4nPrhBlmZio1Eb2SjQuTRGPU6Ea5QSrgkKV9eO8C0/Fkjh6lQ6u8ANqJIC28ethBKPSiK5YRl4sJDEO+o0wLYMZrPmrvrKq+vm/LuGV8PWimOD/h0go2P2mJxfydxZqjJ5gbKu43BlXZ4JqyemjyXWYCaeeuhZqGPo3IxX6aXrDnT8TMAzAPjZmk4IoNFvCozJQwwPc1ov1kto034bz8ffIv1bTJYsvhCoVWvNRq0MgEraKrkXF8OWFeAYGkvbJfq3aK6tyrtWv431Ym57Dj0gL0fie+gxtShRcUqL0sUp5aEg6wnirEInH0fQtJnNQqJh3bvC9qXDiehwZrzDhIR8Jmr/ZPJFO3tmcGFAHdHlKn8jhjDkwLYs4IQyCa/EDNeOS6vUBILcVeQn+fLsgBuuwPRYrULmIMuC40UW7EoWjBUWVLmqy5htzFmwq7LgmH7gSFYeC25T6vLMrsJftEE/hwX7S1hwTFjwGQC5LNjlk9edC6Ylc9add1NzlseC4xwWxHaLLNjNZcFxDgvOYK9AJ1uyIbXXKJ/1EWfGZ/ECnxGc+wqfZRmrb1QbdCMSAy+oG5EFxo7SLPqEkFplGVIL9kezyXpXb1wmJjDsUvKMYPIJzpQzxUerlzmKAnHSYMF+KlGcKcTJ4S91cuSYsL7i7UgW8zuO5hk+30Ngihn6JI9vOEg+9S3RfFb/H5qfylab8nyxWaMb/oRv+H2yuffxL3sD4vxFaHi+4JdqVgZ0algwUiIbfmgLNcVfRMexPaL6LGYGsXd8EuLwDjMeBQVU2bLYJtcTLgVaLHpJV5E+BahWq4MQ8eSruYZne9zhrXSSRTzl6k5WnYyrGwOgHO5YSFKu7hxYPuyuTOqB8nQa3IVObhVvh8lJXpO+pOIo2sBjq/Es1Q4qeap7gPdOiZSGL8glaac4qkM7TC1L/vkkSkGwfBw9x1n93Gg/aWomPJlsL80T6K3aU2AEqg+WYs98sAHLouAC1d3qZ5IcdiaX4ER8soHik/UXt9I34kOES92x4vu7fPNMHb4XmhQ83DNcruqYT7fXHv3Dt/ZY5hMXm2trPNxcakEqnAcsHw1BqQlxWdcbZSXLHpTcPAGOCgeKvrnzwTdX/waPc839FszDb4H+jb5YbZGxUExCHjfmLWDisvxFTGoNNQuWRrgMEyj6Fs7dbyH0XQqB6QATBzEJFzAhmtJVnVQSn1VmtxJKqgXfBnSYbGBzgLA6wE+ewR+m8/ANIODmgPocVbRXB6ueUW0u6kC2ZFcD+haUOmEACYHANkYJV+IzR33zoocixgJ5f8tkHWvkpDEzZwQZSaoUNm4uwQRCOGc5Q//tObvQCEPmHIlKLleQlFjwqKowd6YFfs5quBoswxAKAcPwm6N/c8TEO6hTVvGPMvHB+rHwrEXsWAA2cHL1n8mdG4a7e9wUsJmXhJg1PMrUEWGbnogylW9TeDLKlLtPaG5d5tZFLtsXS4cKzZVdlWVfZdlZWfZWkb1VZG8V2VtF9laVvVVlb1VlYLK3quytKnuryd5qsrea7K0me6vL3uqyt7rsrS57q8ve6rK3huytIXtryN4asrem7K0pe2vK3prKrCnTJntryd5asreW7K0le7NM2R17ZvlVJb+q5DeVfIVXVGZRuUVlF4VfLIVhLIVjLIVlLIVnLIVpLIVrLIVtLIVvLIVxLIVzLIV1LIV3LIV5LIV7LIV9LIV/LIWBLIWDLIWFLIWHLIWJLIWLLIWNLIWPLIWRLIWTLIWVLIWXLIWZLIWbLIWdLIWfLIWhLIWjLIWl2LOULu//qT0KPWIIlBPfzCaFn+r+j+xU1B2JYtXn7lQwX9mpLFRXq8AzNZt+d6fyPDQ8yvVL1RYr4KBzdypLdyJ4trm4ExFALWDUxZ0IFkuEUlVSO5EKWkl5O5Gxo3aSGYKfOt5UdyLLdyFBCiCDk959TJ38gTnK+eby/Yesv7j/oEApadJwBZEkxZTzyaX7D0K33P3HknHivoMTT2xGPLkJ4LsO1jKQOw7Elx7DBewYjkMKlO1GdlMRsHO5nM3EJV/wRpBd8gauYCPgix9vCMlsLULyXWWTRCr4QJ16uUo3EAP8BmhIz+yITxh9dsQn7KZ8wgOcsvjBx4/GbwMmYanJw/HYjoTkMDto6GiiAgqKXz0XQ9XbkR2A6TBnhwXrJNciudWqyO17A3c6TtpitYVGnU/TQH5cQ7zRYqEH3oP+6eq1YAbSX2IX16a4dIkuoZ3h40+IP1SINM2S5nLZiFO962jc0kMaCGnjyqgKFh6Cb5/4yIHUsUkS611EEwijnPlY75hz1iWu9blJD+TIC2jvbNZ+nW+X8IO1SutVS3o5F0H7gCxGNBDnl3FNEg7wTqaAYOADBmgIIwZPfOoERQm7kL/0aDk0BgYiFHCjE4DeihlHDw0jA8nkbWkh0GxHZCacc8pNEnmzny3hgE4QEKmkVk6oM+hWLWQY8kq39LytxbrmWPJ+MeaBPQqMGTsDv3C5gmgptdTKIa+sDDlRAZPxJhwhgQOPHGDwWEcneFafJonsI8npnIet8N73U3kC/RQ1ReUdpbJA4ZaEKy3gyQIIeC1lCtV+lEw2mExEkDKaHCrKbiQtRRajn4qBWht73MX6jG4oNTD4Rp8HUoSeL8qD3xAGLper+BVkkwtBEKoD+rF6wnGPGn7pkBzxiRi3QalZr6Yz6CiYYUU/7OHyVYSvM3FBidFGi4ISc58TlAMQlOIt/4AAzQioAafPgSOwyfwlZaGSW20SrXeMLcgz5NVpwAvJo3t1kbfQIyULanHPYCTJqQX5fG7PaMRcpoowH3eJQ4+iiqFvII1Q5uO7pehWoTIztkkCZS4tJnIuBjmHZwZc0pJXyFDOKiTEQ3N97q8rH+F02fcN2V5EwPwAKlxMO5OnHyQj8PlnJSOHsB8nrMxFlhxQLmaZoaNCFhPzcxE2ayeov7z7PGTfaIQs5H2+QHw4AoPRVpVDfKSKqa6jw2WxpmTTgYRtwly9o7Fic2JDMFDm/AQ3CWg/EsMA62KQAn4WycEDIEOrFMkXQitFj73ztw457OtYkYTjrwfoRsFPjs0D9OyYX0WQH7eGIzsi42CRRZG9Wi3iAdcq0mWdbGre2SyaiIeuMC+REsAi3DRKIItw06gBLdJPo0a2SD+NGuIi/TRqrIv006hBL9JPo0a/SD+NGgYj/TRqPIz006iBMdJPY0iPjC39NIb0yNjST2NIj4wt/TSG9MjY0k9DZoQwIU4JoTqZUUp6sodcpLzDvjGETar8cxb0G2vJqpw41nqRCzCUxZJ59JnklpXcssitKLkVwUcKBhmck9xeM7y3LhlVrpuL5/fsvxfRsZ76XFeR7t7nZrGIm/YIX+J5965CvjBNPsmLARzUCMVgHvb2L3Wizqj+UY7JPfZJCJLVyzkin2WOvUXuIFWZnWCzU3ZWdyaPyHMiL/gBODkiH9vagFcZLwZkaM8BUI/IyUUmWk+ejPf0ks9PuH39W2/hZHwsT7Zn/GScnsr3SuxCCbxwAehUClXH+Ld43vsWA8QSD/ig37Gl33EoxTlRviTMBgOzwJSRX7BBERoqURPyfX+8SVLy0pXkJcI86xkjBuyTgNgndB+66dB9j8PPvfhbTQeolWQuc7kcaawCZLFdL2bR/UDAXwC50VgpWlQy1DbgG10OVcfuZS7b6kookZEpJGiJ5qLB8h54ETYzMg1p70ruAvYLY1V7yIyZjCQ1gnTv2TJKuAyaR4gPduMsDuFGE7OBQcRnorUIIR7Zii7efj1leD1lWDhlkPyx/1w492Ic4Tp9aSGhZ4E+P0mWb0KQgBx3UVsQQRbkHtwKsbeuJ7mHgMncx3gj9RCQokDieTwqdV07Eh8s4ke3FL+qaaoYfvMBnKfDf/z8zkP3yyr+UQ9uQ7yAi/u5oGw1F2NxYpsQxzli5dvLcSLkCe0sUuS8lvYUlvxllIEiQD5EzQSPcw2oMveQMvR7XJac1evflP50q7HPZX+rrkqaHSL5W1zyMQ8EFzcOVvB4oEGA+3uR8sjmXIguCfKESsA574zVo41EL2rHsDNjceXkAxv6hrbPXTDOAiTRzEF0gkwNva1l6hBvDBGjAqgnagMaqqYQQRUEdKZA9QwFAqMTPLBItcQcVpuVRKIsJbaPFLEtNlCRsWxFjnD3MtLZ/puyoRrpkVmfvhLpkV6i9HM30tpQggcyzOiT4AEfgwd8GjyQAGsm6eABZSa5Z/RF4ZGRFC+sh1BZDwuS4lGL0i6VCy1KHckbvBxDB45FbQ+9MYtN5VByG4l5VEIFP/wT4pXKEHEbFf18IQ9ecPHbOzCxXjofaFDETykGVLp+84X72/3GnphUhrYOneYUXJ/ADWxvsQxmlMCm8GDGRT/+N+5HUvBt1ZeinC36k1gDnZdivVD2O1hzvkowToTJczl3j3zuvNT7TST4ziYiU2evw+Lsk6vejXrjHf8wqPRN8N2gx3eBLPbIm3vv3jXxx6rjb7kqnA4auiKoI0LZAvuK28FX3A2+6mbwVe+CrzoVfNWX4KsuBF/1HPiqw8BX/QS+6h7wVa+ArzoDfNUH4Ktbf1/s+FObZuZ3UQfK9thPy/fWkpo8RhBfFn1S712XB2Ls3Gt9qT9XHIETS/9RhKuy1U+djYF0NrKN0H46rlX+JTsBEX6L7ue8qsI1nsmSUFL7L9FgM5WLGwY/W+VA7T6imwnewuGVmCyALDySQ1amZ3NUkh3Rg3G540hkywM8JYoQ8KaMlnSkbSAb+bIR4uDLOiNbcX78/E2ThU7QwcJ+VVJd3a/KDRU/vGcT48nN54Ga9ujuju3q0jveDPFu5NZL9pTuP0N20gao6LF9It87ZjZwBKGFuTrIaZHeDjpyuF4W5hE1PG5ESbRkw/iRWh7E3ljndgXt9kY5G01NsYCZokKUxw08gsPJJVi0uMt11GFF2XrIB1nm+5NluWhGi5MtR0C37kpRlClShwGZlGXpUhEjSFeK1FWh2A87//T2LJFBrSkbi++KvIU9USaY1afBrHl7ovRW7j9ra/Qpdf06lTI8uJqy5hFlc6LZybpJCL8k6mHmJjkkz55fbipnmktyIwRJDkBvyDF7RGFnTlIThU+Xlh1pyuvyN3k9/7OQI/x6BkWQs2smePVz+p5vciOquXR7EmEU1LqHHJlIc45eYyZ36+zWybp68dm3YB7gNCaCMRM8t1vFPypjgjGlC2MPylYlp4ivETCOBAxWPXL641GODDhHZlEqeYwjUzgVk1yGVLrxchnSg5F4OQz5jwU75fetFCUML2uhMNNBiau7YUmm0XB6lVd4DhxhhDD2FMZDyqZhURVK9QXL50BaBFHKIFnagi2JSFQhDK1aT7RniW7KdnAcZEdqBlLDvFhUP6kvUk01Rc1dnqImLk/VUmXUlOWpeqpmPQWzkWpHnXgb/M147r8DBmsrDOA5z272Uxt8utUMUF5FSlQWbmBIVFaSisoKOM/zV3gtsq9t1dVtrUN0EcnjG1ru1Pisefqf6+zZjrjHI7c3ZnN+1nL30RGZYSJr6OoYoSYRIvtRmDXKsBxhl9CeFBMvr37KqbSkpXAAqa4uGU2WiyGdMv52wavb/f/l4H6VVaT2VEOOjIERGz1jjGejfOVzNjIZp5fraccUZXWWyzmWJRmzLzbxljdhXJ7XjnP9s41Z+4R6fOjSWQbsJXgJvtJDKtJ1lAcneaa9nz8O/+9tQhBkimvpSKmoegEIi6ZaCoR6eF8Aws5ulwKh5sMLQFjE0FIgNK7rBSDsVJQ5/2jA0VKIdPO0HGKYj0349zZhXEmmIWIsbNbqz/Pw85MS5WMRvYQFPZxHFUyTNDhrKRrsLH850CAfj+BFPCrV51mbVngRTLX6PHPTCi+CqVWeZ29a4UUwdfpVyJgRt1F+nrg0kHM50Dgfo/hFPJr0I2szIS7NZ/Eg1Z8BSqJtqMQ0rWVsO3sGwCB/IIPnm/RYn/RN6j8LoKfDZpECKJvL5qH3DAA3H2n3JeqXKyah/pj1XjWfpT6t/gzQcT4e47+3CcOV6tlX0/LVtPyaz7LPsZD+2uTPycVXiv1dTX5Lkr7S7m9qEr1S7H+Jp1/awLyS7j+qSfJKsf/5Ju4rxV45+bXJ6+y/Nvn3MmZedsa90u4/qUnwSrH/f22gqy8dxb3S7tX19Nrk1RfyLxFPL52JvpLubzXWXjyAfaXd30juF0M5Xkn32uRPRQK8Uuxv1T2vq/PftEnvlWKvTf70gn4xYPGVdK+n+f9vNAlfKfZqEL42+ZPb45eCd19p9x/VxHml2GuTPy8FXnwv4JV2fyO5X3xB6JV0fx+1Xyn9by15Xnoz65V2/+oZeum1qlfavXoA/3OajF8p9hqK+Rp/8Eq6VxXw2uTVh/kac/La5DWg6jWU/bXJn1wGL35u6JV0r69B/sc0GbxS7HWL+yphXin2eqbw2uQ15Orfqon/SrHXvdZrk9e4ttdY6tcXu18dKa+ke/3c22uTV5fC66cRXr8L8mwTvCfilWr/q8ZX3aJXPs3smbhZit9cyT7GrVzUKT7HrVzYKT7HrV7cKb/Hrd7gKb/HrV7lKb/Hrd7pKb/HrV7uKb/Hrd7yKb/HrV73Kb/Hrd77Kb/HrV4AKr/Hrd4EKr/HrV4JKr/Hrd4NKr/HrV4SKr/Hbcgvb9vye9yG/PK2Lb/Hbcgvb9vye9yG/PK2Lb/Hbcgvb9vye9yG/PK2Lb/Hbcgvb9vye9yG/PK2Lb/HbYxs70lj7JW+/Ijyo3Lvkbw/6C9WdpZUJlcJUnSG/HLq/JuPDG/JfUfOczclLW0k7m/y5P1NiSOv95QXm2Vv8UzYlXuOkfA7TI7k5aP8MhF2WRi5wI6+GMyKMlfuZcvkXWOiSHQia7FOUtDZ68fsFjLl1j1ylShvC+VnAlDE7xWFbEmGwMm5fTBaegXhs5f1pXPVawEdWQVp5cnrC8VTlL2sMHODIB8aG/TCk3qtqXqXYeqSQN/597z9euGGanmN9MIN1X/5FunwN6d8YS3kXpCaZK6vdTLX1yqXkibiAtVEycxASnJv9lVyVX5SLmJ1MtelyrIUB0ydvNtk6XJSb5ON5K1/4prVvMtgPXkdJblLlV9QqLZfqLRw4eqRbCmFQrR4Ba3HyzM352bv1k3dVOeyIS9e5KeyujEQV2MStiSXFjJenH6pfi2aq5pVjOTlHn4pAhjwi3xm4m0pFsAI7Yhc9Bp8G8z9bwO8LlMbfEvmId6ZOaA3TUI14Hp2D6wrbtYs0VtZNZ/dbylKeNd6aUDvrVPK7EBwu2u7gtsnyIKgBSQVBs5vXudM6bu5cJ2zck+vep2yvIZZvduZXrScLN6kjNctK9f+4aXLolJAxVaQ6sxLQ1chiaIlFyfHypBz5F0eA/gD7Y1GlJ7OLq/EuZ0nhDNCGy+bD/DS1AGfvlC5xtfl1/jKzG/u3EUuGIjbUgerLt6WCn+U21J9eoWvaGdD8apv4KyGdkhnlUwyXrfu2wG/YN2cK8Pt/c3DhX6gSmjLO4t9yavBnECg4xX5dBi+HEYpRI7W4O+3cD74FgIlSiEMCpaF+y3QIYOuCBypD4spPdLcYY6dxetZYRyZG1pTl7MKeU4YPcncgJq6pp1d05pzW+oD7bdV1w1yt+Y7oNTI9te9cez9Yhcrr18RA0OBhQNz8E53MTByKydeliqHNPt3HtLA+afG1FXuUKVSl15HjAPTNByVvooAsE82zfQmYnplEqh8kKf3od/X+EYu4bcF4+3FeglbwyZP87I2Cb/aFRTIallwLF1/THi/e2cZJl6RCq0TAgmlZmQneEXi+iIeAgU5vn7GikgZENTiVPWpsGzpHc7cjmXKLkINr9wCnPBrdheNBy9tGTpUE2YgoqY90xK641CQHi0VEUQHqHKCXVzOTT/1xvLsfeNa+u5ytP0SsPh4Q7Tg0m1TObR5KotDyLvCXA5msoTDuGYnnCYZTfAOCDg2nzA2nHE2PiiCniKddKXgqw7dBn4ANvKBm4jQipD/PcpB1OdQIkk5OAZczUReVG4bvlNu0uUCj/AmMUH0osZuaO9TyesgdlDs6cC9NGVuaA+abtxqFmwHVy29rbHaYD87Bqv1B7TpaDpexExuP76H5w1ZUWmNsCV63xfMJ/ir3uy8QUym7yAlgN3qtVql9g7I7uAozWIRqYqXcWNKf6s55K9OMPD0jagNHeptnDkUNvMtLUIMK0Uk2iq7Khpv1XZgt4vkhh9H4jZ0Xrr1XLntnE40ucteXB1usKvG/exV4zDvvri63Ft2pzgU/uZ96MrO+z4jOeRC5OKD7Obp9eFNxFaYorD0T+h0kBuPycZvW1x9rBu7jkaKlKuWMxKgk7L/U12TnQC/GxZorfojaq0ySA12PzT1eqRrUJwz1fLujX5Y3ILy3ScuWDJWvuskciURa4ksJJE0Ujs8Mj1RWkDcLiV0SljLISdpF0zCRrK4j97LET2Ivcexx7TkF42qIzEQvKD7DV0BKYRP/rnJcdJTkyL31t803ymgu4rEwtF6NopvIgzYjeRoHpAbyZ3UjeSZ8W6KCdrJGDu6sSO8WuyScspMsvGBaLy/0Hj/pcbHjCyuI9vCFs5Jt9OfcIynjv1FXhONrZiUHmrQxnwycgvTmXlWUIpZErtcqxWBRHsaCEQjAIYBkWmC/DFSckdhGwLAIFQHLL4ymfzruzeJe5F/l3jB98i7G7s97/vEm4TRDCeNVnqjWfVGo1G2asUu5M7n+AuGDsucz8tWtVFtVurV5jtaAXWw91BIIGHgg48PU5IX4uOAPLq8OOYPPf4w5g+IBkhpEOi6/mR8H0SeJ7hpUX5ntytkuL+oQrSqlcpXKABN0Sxpq80i27tzzaEjN/bDX9AMt8+eDVUiAOiSFlBG7Fwo5SbAKvUkv9EquNumpMJOwUwg8CMAaBCHFXZoriZUW/xhvvOIWpMtNIZf9StVdaGuY0cVSFSKTJ8P6CEEwuAWMGljfbVxP8iK7dVy0UN/F0uC8cHN4rBEVZSvr7t2aHhguXcjz719wiERtMq1OumXdhiyEw66QGkOPd4QCln/hSiUWyhsyd/i/9HAbiHgKjo6OdR+lPtKHeUsxctUC1hf7CDES3XNJoj0rpJK1KozMjk2TSjz9kapRYeBnMF6pfXn5hMusXXYNg+4awevQccrfakx5tmR4diJAlSphgBoNZ1AXWe1n4Rke8J2BTdF4OkXl9PFUy56dZ8eRv7YA6mBLBKQYfJ5KIupmX6pm2XQ+o4wF1WyvNEWym0+bRWTThv8pdPmZCeMIsvAUCYNOO1YLxsBGXQ7kCQiHSzOPDviCgyVnSgsMPuUW2sd9UQMdIlSm80tq8+O0rL1Wdec0jSRouUbbUD43Q7JOiwWLS4L+CIjxCvDCk4trIhMFV9YHggdRIv69zzBEXwx1xiRBhTawOYFaJZ7xDVHEvbAYPVtN9XBAOfXpTKciwcuNFQJUAW+4oucCgRQRTlSZSAEh8TFUnGxBC4AMszgIqTIgPpqdHRtESmHANi6jFJyxGE0lXKEi7KUHHGWypGIyhHBRU7eOnG4GGOwU3JjsExuDFS5MVDlxmCZ3BhIueEocmPwvyE3IOVRjk4TdRlNSH2V5825nxrwogTx0hJkkJUgotx2lkkQT18uOfyU5BjoGz6VHL4iORw+fmVF+4bKN4rAECfsnnqPtaOn66siQ5y+Z1qkpYPK9gFRpQGTXGQ52jnLsZBafQFZfZEdIPcagVgSrC7sBLlBApyuF4Fu0Qama41andj9ZOtPZ7Kt8ZXhzbGika5Erw+HhZZtyynqqreEU/HCtS7DWeieNAgdeJDOO7pBPDKYpr7Bbb53ZFgbFauND1oDdlq2VV3VtFrZhG0B4RYNXe4m2IVsgv+w6sWmrovn6jyvwlwrV2uNuokQlwLB/D/Tk/IM1MFdIQyrRDtSSvBvDavCf0VrDtWsNnXuEBHp8oiMhCZMsTYpHets9zJniwKsU6Al7CTbVPo4ICyZMUqUxrrHClCOijAT6Jt5SfVfdGsbALoVy6Z+7g2zXa6tEhPLQjzXqUBArwWyO7W9LMU3sa7LLhzRhc278LgALXhP1H0JOSB4IoVluHJVTRWVmVwGwVFW0oCf13qCGw0pj0nzcAHQIGsMib6Z5cTFjjOPxNHab+KYWuRSAza+EocfmPHmXGM5oN0Y8WERWI3yujppIMrJkNZ55VXrCf4Z3yfueBz22lsGbqB6d7P2IXmKvaT9aHyPu9Ft+86BB78/uom/+4GfaHQjw735vhEarjEwYqNnjI2Z0eVqfg+3jjjPgE8ZN9szG5ec1rVnjN1wHXC/D+P1itElteipC5OcvAgH9N3RLKPZ1I0xT8x0VTCOjV62gJKyZ8SZAhaTFJNDHlLQpQUsAGkAuKQLWFxRl5zrU1Cw2lhZnc1euFjGYoxC4i9WUWABRT7x0KoFLKYoMaJsAe0mwhA8UQA0NtnuZk4fxvyhxx9i/jDgD13+4PKHkD/4/CHhDxF/0GTskj3TcWWD6QwYqM4A4Y9C7si4UkGp8YPhMldzLNmkvlCaorPDU3RKeKqWKqOU56l6qmY9BbORatdItaND2tACtF5gsYKg+YJs+5U4Kiw1r0LzympeleZV1LwazauqeXWaV1PzGjSvruY1aV5DzWt9ZZ78es1KWVEJO4io19JhfH46eq9eq2Ti7hrYTyq6rlmuZiLrmuVaJiYOtFY6cM3CY7Zy3aqDLMBTHouu2Bo5fis3zaahzvBilYpXMdRZz6lRNk1DZQVD87NVKmbVUPkjp0pVQGERgGpHZLlirUaTA2IRgXm1qlajbqhMtoh0tVLnI28sGVe1VucYNepLqjRqZUPl0UwVXE46LN02OUmv60/U+moSI1FI7ltvduf6keIpFeuyQJxv5nxXetsMZuo1v+IKRwkeEfhYbVPDWEsSmUMP5PLqaociZHDuGPjWMCDqIaLeIlLfu27sPR+1tZ46PyW9GWiAEr/WLp7LGIlOUEwoijRDdnUX+fdu4mGX37uzxIs14ca0ytXmMxUpdqJ2qu60O/Z7uTBhxMvrZUACGWXd2OtBNqdG/OAnvRE5MlgmY3OO0YXbv05MwIRtDdDpkDCDI4DcFhUu5LlJni1yAEV2heiOJTaGR8QP0cgMkE79tkS58xI1X8LW0OPr6KvkrwcM20T/74D3BzqFJFqiGUVDI0dsJdJKc7553BLOtDZMeSTCVAwWayM70SlMsJJKmtKHXsp0/0RJh759j/r2KbPqv3owRQWrLZbIKfIU4/hI4fl1rLiqVHwv1ke6Xt8buNNxwivWn3iL7Nwry+GFQ2y+KgJlVSQb5DSZIQwgArouMOu9zFrsNMPALeDf/izYBPvwu+/7nOX4flDgAx05X6wiVe5f0QYhPPRkeHHiAtvHo9PE7d2e3rk9j0qfkU1FzJMx9JIzb3J34iWm7Nmc3z0Z0TQ4CuPk1EsQpycjVmo6+q87AoJmjyLvgQI2jcl8rk1IGSAQY78OmrcLh88j2wL2GuEeEZYJP9bRi6sWynSPtT2BIYQRcd2PeIdkLO69p+I7Aktam6658WRnHHbdsRMNDZL86HcjN5phGqy0xLGna8uPLmzPeabUCHDDtkbOEkhNfIBemAFPsugjySS2PM0kjywT6MUz4REz0cInWfhAMqSlT/NlWilmklutwbIWKxF+zqlJ8pXqC5JXbbNQ+FzDhR7za6ggMhI61ThT9kyzxY7zKigA6OJTW9CchSoLkJXsnMrZMaj5UD1nbWLtnGyorKxSrKQkoVBZqFioJKEwTreMUy352uUl+IzZYtWSApHiRWxRikKW1g0fl5dYn6IcE8RDtqZIMyxVknS1QiY8PER+4jlR5M7OwgO6MLeNc3SRftDO8ZTws31unENXgBOw1DZszzfUhPbZcPW2W/oMGM3nLBI1RNwiz+13/AAEAgBan+CgtdAxmjrxEvy6KpWg+0kICy2MTqbBe+/OC/pe0PO9uFhcVqJd6UQbDBxbWgegNNZwqj96wTAZwY7LIUeX536QNMnQoIpuUAwQAeyXDHUPuvDdsf/Ti068H1MgbbHY98Ze4hWWV4GBxXdhAHyoYgAEu1pd/edGZMBW8wrQDqbj8RvbvobH3thzo70g8aJ7d6xd68a1jaW6sa/zg9X99X2SZ4BwBoGsP62r8dH6LzoDTjwLetq5MXAkuvqvZBSFDyu9cDruF4IwKYxDt1+gAy74csSFldL5Ez0ynzr2D5xHZC1HHzjwu9adDgYemCPckbycZvovNYSXeVTs5fXRvyXojH3CfggoQ3g8mQI11RQ38H88g8D5yUd6rBRxF28PQIdjb+3BBTtqxS3cRWF37E0KsQfKopCEhRGsJPi5g6ny+gUwTEeFg7A/hSZLsS5QhNpAN45cacUoQI/RzA+GSE6d+HTJDOEJAqPhE4Zk6k+/wXQbKDv8iRdOEy3GE/f2M43cfn/r3guSj34MKtaLtBWc6BUjdnR29AZopMONkTf8eC1wJ569svXoJ6dkGCsGyZ54cewOoeQoCoeROykAg05gjSecQh600GD0pRWdNaFksJ10uK/CEB7h1R7IJq8PawNEjpKy35hGH7Iu8H9M3GjvdQyPvMRVHAZQJQFqyLH3caXl5Wu6ugAIt96B6IaKZAOwwgtXbDuZ3XnhoCAq4MEEf7a/iEcwcsXz2pjInnUduZrnxSN/kEC/h2vTgD47VHo56zfaIexcdTBMHTC15iCQo+F0AlMVG+a7KxjsAq6R9zyqpJxiSh4JouSJ4kke02jSLI7lWR6WZ4glRSk7R8CIlDc21IS2AuUBMPva2tqKbijcqowoPzcFZQUsWksnss3AeEKPECsVq8vEWAHn2+mGUUKnnjxiRIpjk6VGRMWGRuJXSOzK/unhJ2DLCJD0B0Q3tFdWjD5y14pLGlMGXit0pv6YMfZqXHBOT7dOzvYOP53aVgEmogCrDuReMAjXVshZbs8BmoZJiJNCNNBWFIWRvoaiJommPRD+ds8x9oXqKjhZ3oe1gYytUnqfODaI6WGPUWUTHO0+PsIUIos/yxZYgfMFPjPGwEfgDPOdSAnmkDl34Z2mg6RaiAHH00ob6CoOzNbpXIhRayune+93Cx4+E3moZ4PjxY6iQ0Tg2iAKJ1pGb0/Xdreco/MmE5MkNlpPBz8DF0SzX2yrAMknsEx6I8zP5zKKp/MEovOJ70mna0GIso5JDeQENhHpkwDjH/ZyYxiKHcd+xkzXMCrczjdeoewXBfjBm3Uwp/0Pg0EQOY5jkMrtyIG9JMhzWhgrCpVtirR/wNJRkg4saSQTVZQLWxYaf5rYM3wxwMGoLpvM0T/E+xow75GCYTtQkGsnuLM94mUyJq3gbKTmVl9LwlOy7qBOO11EdsdHAuZSIMlyIAlMKDAHqKPxePaL8IYxInr1yeiFk7tp4p2mvE3U2ZYiWpAmGr4pJtKRg4J00WDGV2n1XFMaqBlIwocLc4+vU+HrF66tjgNoHRpAfx/YBYQen4Jow5VDR5tbHWpChhqQXx8HjBul9l9gKRG/lyJPtISnEjt/G4yv9xnOBp7QUp6KDEpVwmkp9kpU9vJV9gp+j7385Zzh/zZ7Pc+jafbyCLWjJewl3spLU9DPMFj4ewwWLGUwX86Ca+duo7WAnFpGdBoGWV5zkdfCNK8lGwNJh0RvD9Rxcy7D31DHc1W0EQ67N14vWUMp/NPThsQztIbI6Ov/F9sO7OA="},
            'sjcl.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"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"},
    };

    /**
     * @desc Compressed Diceware word list provided by the official Diceware website for passphrase generation.
     * @see https://world.std.com/~reinhold/diceware.html
     * @type {string}
     */
    const DICEWARE_WORD_LIST = _zlib.inflateSync(
        Buffer.from(
            `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`,
            'base64'
        ),
        { windowBits: 15 }
    ).toString( 'utf8' ).split( '\r' ).join( '' ).split( '\n' );

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
            return '2.0.4';
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
                exchangeBitSize: 751,
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
            /* Due to how BD loads the client, we need to start on a non-channel page to properly hook events. */
            if( [ '/channels/@me', '/activity', '/library', '/store' ].indexOf( window.location.pathname ) === -1 ) {
                /* Send a synchronous alert to indicate the importance of this. */
                _electron.ipcRenderer.sendSync(
                    'ELECTRON_BROWSER_WINDOW_ALERT',
                    `It seems that Discord has not been loaded on the Games or Friends tab.\n` +
                    `DiscordCrypt requires Discord to load on the Games or Friends tab to work correctly.\n` +
                    `I'll reload the client once you click OK so that it starts on the correct tab.\n\n` +
                    `\tPath: ${window.location.pathname}`,
                    'DiscordCrypt Error'
                );

                /* Relaunch the app completely. */
                _electron.remote.app.relaunch();
                _electron.remote.app.exit();

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
                if( !attachments.length ) {
                    event.originalMethod.apply( event.thisObject, event.methodArguments );
                    return;
                }

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
            let encodedKey;

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
                `Algorithm: ${remoteKeyInfo.canonical_name}\n` +
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
                    `Algorithm: ${k.canonical_name}\n` +
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
                    parseInt( _crypto.pseudoRandomBytes( 1 )[ 0 ] )
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
                    parseInt( _crypto.pseudoRandomBytes( 1 )[ 0 ] )
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
            let file = _electron.remote.dialog.showOpenDialog( {
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
                    _electron.clipboard.writeText( `Delete URL: ${deletion_link}` );
                }
            );
        }

        /**
         * @private
         * @desc  Uploads the selected file and sends the encrypted link.
         */
        static _onUploadFileButtonClicked() {
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
            if ( !_original_fs.existsSync( file_path_field.val() ) ) {
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
                    _electron.clipboard.writeText(
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
            /* Create an input element. */
            let files = _electron.remote.dialog.showOpenDialog( {
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
                if ( !_fs.statSync( file ).isFile() )
                    continue;

                /* Read the file. */
                try {
                    data = JSON.parse( _fs.readFileSync( file ).toString() );
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
            /* Generate a random captcha that's easy to solve to verify the user wants to do this.*/
            let captcha = _discordCrypt.__generateWordCaptcha( { security: 32 } );

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
                        let file = _electron.remote.dialog.showSaveDialog( {
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
                            _fs.writeFileSync( file, JSON.stringify( data, null, '    ' ) );

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
            const replacePath = _path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );

            /* Replace the file. */
            _fs.writeFile( replacePath, _updateData.payload, ( err ) => {
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
            const replacePath = _path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );

            /* Replace the file. */
            _fs.writeFile( replacePath, _updateData.payload, ( err ) => {
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
                'Please enter the approximate security level you\'d like this passphrase to have below.\n' +
                'Be advised that a minimum security level of <b><u>128</u></b> bits is recommended.\n\n' +
                'Read about Security Levels ' +
                '<a href="https://en.wikipedia.org/wiki/Security_level" target="_blank">here</a>.\n\n',
                '128'
            ).then(
                ( value ) => {
                    /* Validate the value entered. */
                    if( typeof value !== 'string' || !value.length || isNaN( value ) ) {
                        global.smalltalk.alert( 'ERROR', 'Invalid number entered' );
                        return;
                    }

                    /* Generate the word list. */
                    let { entropy, passphrase } = _discordCrypt.__generateDicewarePassphrase( {
                        security: parseInt( value )
                    } );

                    /* Alert the user. */
                    global.smalltalk.prompt(
                        `GENERATED A ${parseInt( value )} WORD LONG PASSPHRASE`,
                        `This passphrase contains approximately <b>${
                            parseFloat( entropy ).toFixed( 3 )
                        } bits</b> of entropy.\n\n` +
                        'Please copy your generated passphrase below:\n\n',
                        passphrase
                    ).then(
                        () => {
                            /* Copy to the clipboard then close. */
                            _electron.clipboard.writeText( passphrase );
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
            let currentKeys = _configFile.channels[ _discordCrypt._getChannelId() ];

            /* If no password is currently generated, write the default key. */
            if ( !currentKeys || !currentKeys.primaryKey || !currentKeys.secondaryKey ) {
                _electron.clipboard.writeText( `Default Password: ${_configFile.defaultPassword}` );
                return;
            }

            /* Write to the clipboard. */
            _electron.clipboard.writeText(
                `Primary Key: ${currentKeys.primaryKey}\r\n\r\nSecondary Key: ${currentKeys.secondaryKey}`
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
            return _fs.existsSync( _path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() ) );
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
            const BETTERDISCORD_PATH = '/BetterDiscord/plugins/';
            const MAC_PATH = `${_process.env.HOME}/Library/Preferences`;
            const DEB_PATH = `${_process.env.HOME}.config`;

            switch( _process.platform ) {
            case 'win32':
                return `${_process.env.APPDATA}${BETTERDISCORD_PATH}`;
            case 'darwin':
                return `${MAC_PATH}${BETTERDISCORD_PATH}`;
            case 'linux':
                if( _fs.existsSync( _process.env.XDG_CONFIG_HOME ) )
                    return `${_process.env.XDG_CONFIG_HOME}${BETTERDISCORD_PATH}`;
                return `${DEB_PATH}${BETTERDISCORD_PATH}`;
            default:
                _discordCrypt.log( `Unsupported platform detected: ${_process.platform} ...`, 'error' );
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
            const plugin_file = _path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );

            return _fs.existsSync( plugin_file ) &&
            ( _fs.lstatSync( plugin_file ).isSymbolicLink() || version.indexOf( '-debug' ) !== -1 );
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
                // noinspection JSIgnoredPromiseFromCall
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
                        localFile = _fs.readFileSync(
                            _path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() )
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
                            // noinspection JSIgnoredPromiseFromCall
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
                        // noinspection JSIgnoredPromiseFromCall
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
         * @param {{[words]: number, [security]: number}} options The word length of entropy level desired.
         * @return {{passphrase: string, captcha: string}}
         */
        static __generateWordCaptcha( options ) {
            /* Stores the result captcha. */
            let captcha = '';

            /* This uses a converter to transform the text. */
            const CONVERTER = [
                    /* REGULAR */
                    `ABCDEFGHIJKLMNOPQRSTUVWXYZ!"#%&'()*+./:;=?@$0123456789`,

                    /* SMALLCAPS */
                    `ABCDEFGHIJKLMNOPQRSTUVWXYZ!"#%&'()*+./:;=?@$0123456789`,

                    /* SUPERSCRIPT */
                    `ᴬᴮᶜᴰᴱᶠᴳᴴᴵᴶᴷᴸᴹᴺᴼᴾᵠᴿˢᵀᵁⱽᵂˣʸᶻᵎ"#%&'⁽⁾*⁺./:;⁼ˀ@$⁰¹²³⁴⁵⁶⁷⁸⁹`
                ],
                ALPHABET = CONVERTER[ 0 ].toLowerCase();

            /* Generate a random passphrase. */
            let passphrase = _discordCrypt.__generateDicewarePassphrase( options );

            /* Split the passphrase into words. */
            let words = passphrase.passphrase.split( ' ' );

            /* Iterate each word to build the captcha. */
            for( let i = 0; i < words.length; i++ ) {
                /* Generate a random sequence to pick the word list from. */
                let rand = _crypto.randomBytes( words[ i ].length );

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
            let v = _zlib.deflateSync(
                Buffer.isBuffer( data ) ? data : Buffer.from( data, format ),
                {
                    level: _zlib.constants.Z_BEST_COMPRESSION,
                    memLevel: _zlib.constants.Z_BEST_COMPRESSION,
                    strategy: _zlib.constants.Z_DEFAULT_STRATEGY,
                    chunkSize: 65536,
                    windowBits: 15
                }
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
            let v = _zlib.inflateSync(
                Buffer.isBuffer( data ) ? data : Buffer.from( data, format ),
                {
                    level: _zlib.constants.Z_BEST_COMPRESSION,
                    memLevel: _zlib.constants.Z_BEST_COMPRESSION,
                    strategy: _zlib.constants.Z_DEFAULT_STRATEGY,
                    chunkSize: 65536,
                    windowBits: 15
                }
            );

            return outForm ? v.toString( outForm ) : v;
        }

        /**
         * @public
         * @desc Loads all compiled libraries as needed.
         * @param {LibraryDefinition} libs A list of all libraries to load.
         */
        static __loadLibraries( libs = EXTERNAL_LIBRARIES ) {
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
                    _vm.runInThisContext(
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
                        _vm.runInNewContext(
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

            /* Calculate a random salt length. */
            let saltLen = (
                parseInt( _crypto.randomBytes( 1 ).toString( 'hex' ), 16 ) % ( MAX_SALT_LEN - MIN_SALT_LEN )
            ) + MIN_SALT_LEN;

            /* Create a blank payload. */
            let rawBuffer = Buffer.alloc( 2 + saltLen + rawKey.length );

            /* Write the algorithm index. */
            rawBuffer.writeInt8( index, 0 );

            /* Write the salt length. */
            rawBuffer.writeInt8( saltLen, 1 );

            /* Generate a random salt and copy it to the buffer. */
            _crypto.randomBytes( saltLen ).copy( rawBuffer, 2 );

            /* Copy the public key to the buffer. */
            rawKey.copy( rawBuffer, 2 + saltLen );

            /* Split the message by adding a new line every 32 characters like a standard PGP message. */
            return  ENCODED_KEY_HEADER + _discordCrypt.__substituteMessage( rawBuffer, true );
        }

        /**
         * @private
         * @desc Returns the canonical name for the given exchange bit length.
         * @param {number} bit_length One of the supported ECDH or DH bit lengths.
         * @return {string|null} Returns the canonicalized name on success or null on failure.
         */
        static __exchangeBitLengthToCanonicalName( bit_length ) {
            /* Elliptic Curve Names. */
            switch( bit_length ) {
            case 224:
                return '`secp224k1`: *SECG Koblitz Curve Over A __224-Bit Prime Field__*';
            case 256:
                return '`x25519`: *High-Speed Curve Over A __256-Bit Prime Field__*';
            case 384:
                return '`secp384r1`: *NIST/SECG Curve Over A __384-Bit Prime Field__*';
            case 409:
                return '`sect409k1`: *NIST/SECG Curve Over A __409-Bit Binary Field__*';
            case 521:
                return '`secp521r1`: *NIST/SECG Curve Over A __521-Bit Prime Field__*';
            case 571:
                return '`sect571k1`: *NIST/SECG Curve Over A __571-Bit Binary Field__*';
            case 751:
                return '`sidhp751`: *Post-Quantum Supersingular Isogeny Curve Over A __751-Bit Prime Field__*';
            default:
                break;
            }

            /* Standard Diffie-Hellman. */
            if( bit_length >= 768 && bit_length <= 8192 )
                return `\`Diffie-Hellman\`: *__${bit_length}-Bits__*`;

            return null;
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
                let output = {};
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
                output[ 'canonical_name' ] = _discordCrypt.__exchangeBitLengthToCanonicalName( output[ 'bit_length' ] );
                output[ 'algorithm' ] = _discordCrypt.__indexToExchangeAlgorithmString( msg[ 0 ] ).split( '-' )[ 0 ]
                    .toLowerCase();

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
            let type = _mime_types.lookup( _path.extname( file_path ) );

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
            let { clipboard } = _electron;

            /* Sanity check. */
            if ( !clipboard )
                return { mime_type: '', name: '', data: null };

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
                    tmp = clipboard.readText();

                    try {
                        /* Check if this is a valid file path. */
                        let stat = _original_fs.statSync( tmp );

                        /* Check if this is a file. */
                        if ( stat.isFile() ) {
                            /* Read the file and store the file name. */
                            data = _original_fs.readFileSync( tmp );
                            name = _path.basename( tmp );
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
                let params = _discordCrypt.__up1SeedToKey( seed || _crypto.randomBytes( 64 ), sjcl );

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
            try {
                /* Make sure the file size is less than 50 MB. */
                if ( _original_fs.statSync( file_path ).size > 50000000 ) {
                    callback( 'File size must be < 50 MB.' );
                    return;
                }

                /* Read the file in an async callback. */
                _original_fs.readFile( file_path, ( error, file_data ) => {
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
                            _crypto.pseudoRandomBytes( 8 ).toString( 'hex' ) + _path.extname( file_path ) :
                            _path.basename( file_path ),
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
                _crypto.pseudoRandomBytes( 16 ).toString( 'hex' ) :
                clipboard.name;

            /* Detect which extension this data type usually has only if the file doesn't have a name. */
            if( clipboard.name.length === 0 ) {
                let extension = _mime_types.extension( clipboard.mime_type );

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
                    let form = new ( _form_data )();

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
                    let form = new ( _form_data )();

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
         * @desc Generates a passphrase using the Diceware word list.
         * @param {{[words]: number, [security]: number}} options The word length of entropy level desired.
         * @return {{passphrase: string, entropy: number}} Returns the passphrase and approximate entropy in bits.
         */
        static __generateDicewarePassphrase( options ) {
            const MAX_WORDS_IN_LIST = DICEWARE_WORD_LIST.length,
                ENTROPY_PER_WORD = Math.log2( MAX_WORDS_IN_LIST ),
                DEFAULT_SECURITY_LEVEL_BITS = 128;

            let passphrase = '', { words, security } = options || { security: DEFAULT_SECURITY_LEVEL_BITS };

            /* Determine the number of words to generate. */
            if( security && !isNaN( security ) )
                words = Math.round( security / ENTROPY_PER_WORD );
            else if( !words || isNaN( words ) )
                words = Math.round( DEFAULT_SECURITY_LEVEL_BITS / ENTROPY_PER_WORD );

            /* Generate each word by picking a random number from 1-2^32-1 and rounding off to the nearest word. */
            for( let i = 0; i < words; i++ )
                passphrase += `${DICEWARE_WORD_LIST[
                    Math.round(
                        parseInt(
                            _crypto.randomBytes( 4 ).toString( 'hex' ),
                            16
                        ) / 4294967296.0 * MAX_WORDS_IN_LIST
                    )
                ]} `;

            /* Return the result. */
            return {
                passphrase: passphrase.trim(),
                entropy: ENTROPY_PER_WORD * words
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
                if ( remove === undefined ) {
                    /* Allocate required padding length + message length. */
                    let padded = Buffer.alloc( message.length + paddingBytes );

                    /* Copy the message. */
                    message.copy( padded );

                    /* Copy random data to the end of the message. */
                    _crypto.randomBytes( paddingBytes - 1 ).copy( padded, message.length );

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
            let isValid = false;

            /* Iterate all valid Crypto ciphers and compare the name. */
            let cipher_name = cipher.toLowerCase();
            _crypto.getCiphers().every( ( s ) => {
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
                /* Assuming this is a ECDH/DH or Curve25519 object, operate directly on the object.  */
                if(
                    private_key.computeSecret &&
                    typeof private_key.computeSecret === 'function'
                )
                    return private_key.computeSecret( public_key, in_form, out_form );

                /* Assume this is an SIDH key pair and call the method to generate the derived secret. */
                let ret = global.sidh.computeSecret( Buffer.from( public_key, in_form ), private_key.privateKey );

                /* By default, sidh::computeSecret returns a Buffer. Convert it to string form if necessary. */
                return out_form ? ret.toString( out_form ) : ret;
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
                key = _crypto.getDiffieHellman( groupName );
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
                    key = _crypto.createECDH( groupName );
                else switch( size )
                {
                case 751:
                    key = global.sidh.generateKeys();
                    break;
                case 256:
                    key = new global.Curve25519();
                    key.generateKeys( undefined, _crypto.randomBytes( 32 ) );
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
                _salt = _crypto.randomBytes( 8 );
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
            _encrypt = _crypto.createCipheriv( cipher_name, _key, _iv );

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
            _decrypt = _crypto.createDecipheriv( cipher_name, _key, _iv );

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
                if ( !_crypto.timingSafeEqual( computed_tag, tag ) )
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
            /* Perform the encryption. */
            return _discordCrypt.__encrypt(
                'bf',
                cipher_mode,
                padding_mode,
                message,
                key,
                to_hex,
                is_message_hex,
                /* Size constants for Blowfish. */
                512,
                64,
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
            /* Return the unpadded message. */
            return _discordCrypt.__decrypt(
                'bf',
                cipher_mode,
                padding_mode,
                message,
                key,
                output_format,
                is_message_hex,
                /* Size constants for Blowfish. */
                512,
                64
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
            /* Perform the encryption. */
            return _discordCrypt.__encrypt(
                'aes-256',
                cipher_mode,
                padding_mode,
                message,
                key,
                to_hex,
                is_message_hex,
                256,
                128,
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
            /* Return the unpadded message. */
            return _discordCrypt.__decrypt(
                'aes-256',
                cipher_mode,
                padding_mode,
                message,
                key,
                output_format,
                is_message_hex,
                /* Size constants for AES-256. */
                256,
                128
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
            let _message, _key, _iv, _salt, _derived, _encrypt;

            /* Pad the message to the nearest block boundary. */
            _message = _discordCrypt.__padMessage( message, padding_mode, 256, is_message_hex );

            /* Get the key as a buffer. */
            _key = _discordCrypt.__validateKeyIV( key, 256 );

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
                _salt = _crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            // noinspection JSUnresolvedFunction
            _derived = Buffer.from(
                global.sha3.kmac_256(
                    _key,
                    _salt,
                    128 + 256,
                    ENCRYPT_PARAMETER
                ),
                'hex'
            );

            /* Slice off the IV. */
            _iv = _derived.slice( 0, 128 / 8 );

            /* Slice off the key. */
            _key = _derived.slice( 128 / 8, ( 128 / 8 ) + ( 256 / 8 ) );

            /* Create the cipher with derived IV and key. */
            _encrypt = _crypto.createCipheriv( 'aes-256-gcm', _key, _iv );

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
            /* Buffered parameters. */
            let _message, _key, _iv, _salt, _authTag, _derived, _decrypt;

            /* Get the message as a buffer. */
            _message = _discordCrypt.__validateMessage( message, is_message_hex );

            /* Get the key as a buffer. */
            _key = _discordCrypt.__validateKeyIV( key, 256 );

            /* Retrieve the auth tag. */
            _authTag = _message.slice( 0, 128 / 8 );

            /* Splice the message. */
            _message = _message.slice( 128 / 8 );

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
                    128 + 256,
                    ENCRYPT_PARAMETER
                ),
                'hex'
            );

            /* Slice off the IV. */
            _iv = _derived.slice( 0, 128 / 8 );

            /* Slice off the key. */
            _key = _derived.slice( 128 / 8, ( 128 / 8 ) + ( 256 / 8 ) );

            /* Create the cipher with IV. */
            _decrypt = _crypto.createDecipheriv( 'aes-256-gcm', _key, _iv );

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
            _pt = _discordCrypt.__padMessage( _pt, padding_mode, 256, true, true );

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
            /* Perform the encryption. */
            return _discordCrypt.__encrypt(
                'camellia-256',
                cipher_mode,
                padding_mode,
                message,
                key,
                to_hex,
                is_message_hex,
                /* Size constants for Camellia-256. */
                256,
                128,
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
            /* Return the unpadded message. */
            return _discordCrypt.__decrypt(
                'camellia-256',
                cipher_mode,
                padding_mode,
                message,
                key,
                output_format,
                is_message_hex,
                /* Size constants for Camellia-256. */
                256,
                128
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
            /* Perform the encryption. */
            return _discordCrypt.__encrypt(
                'des-ede3',
                cipher_mode,
                padding_mode,
                message,
                key,
                to_hex,
                is_message_hex,
                /* Size constants for TripleDES-192. */
                192,
                64,
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
            /* Return the unpadded message. */
            return _discordCrypt.__decrypt(
                'des-ede3',
                cipher_mode,
                padding_mode,
                message,
                key,
                output_format,
                is_message_hex,
                /* Size constants for TripleDES-192. */
                192,
                64
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
            /* Perform the encryption. */
            return _discordCrypt.__encrypt(
                'idea',
                cipher_mode,
                padding_mode,
                message,
                key,
                to_hex,
                is_message_hex,
                /* Size constants for IDEA-128. */
                128,
                64,
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
            /* Return the unpadded message. */
            return _discordCrypt.__decrypt(
                'idea',
                cipher_mode,
                padding_mode,
                message,
                key,
                output_format,
                is_message_hex,
                /* Size constants for IDEA-128. */
                128,
                64
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
