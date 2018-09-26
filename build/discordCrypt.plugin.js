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
        `eNrVfOeWoura4K0wddY33znLrg2iGHr36bWIimQkiH9mkUEQkCDimuuYX3N1cyXzopYVujru3hOqe5X4hienN1CfvPgIxd6/Hzz3MT/6ZWp3D5Cb2lX1qukz9OnLgY9Nkea29874R9fPar8MYj8F3VXdpT7ojqsC9H3M8sz/E0C8gnyeWzapXz7aaRxmfS/0Kc6KpobqrgCTa/9Uv0R06Xu8IbiRFcSp/1jYdfQAXX9uiNvYq6OP0BBB/uPPwva8OAs/Qmhx+nNvl2GcPaZ+UH+ExqDhASp928uztIPquO7nMgAmJPcw4QtNTlPXefaCkFvD/QlQBmRQ+Q83wq+tdxorP/Xd+pnUR6fOHl4SW+fFR+hx1hPTI4Q+VYX9El+d52kdF9fOr/U+XsT1eX1BBuHQhQsth/SLwj7B/awrgD8u/3pI98ZP8JXmXkMwUFH/2cOzgWxeoro1AZnlLWhCEaCfPAVPQ3T2Wid7v6rs0H8x5fIDrMH1ozz1/PLfD3RvMJCddVCvoToGMu2HQ3UOVX7mQW1cR1CXNyV0gwb98ccfD9DePqV+FtYRQDsDJHz+BD9h+baFPck7yLP6sYrP/sdhbwHQzUAenRzIYP9xiDxp4maOL/nygHx7Sh/dyHcTJz+9tNDntqshPH9/ZZyvbBC5obpo9fWAi11gFxv9ijF82xYuONkA8jPbSX3vA2RDT+RDaZwlQMBpCjl+L+0astM8C68yryMf6rm9jqoju4ZcgAeMbCrfu4AFOrrA8p8Hx/u978V27afdG/OC1r06qSfcfA/1Rf/d5P5e1WX23n8s7czL9/9faq8X9DX8XuT9nxXUc3RX4pUzIBoPAs4MARh+VvXifhqQ+EX9VjHq06RrvBB7gN/RTFUDc+h/PTp2+YL72IP+Dd2FfSX0sR/XVA8v5/bTgBpqoLaHN+EaSBP+MXv4VmB+A/WSA14HpxtxfRz+/BQfvwyAv4b9vbTwPXqAc7l+eqWn1wqZ5pX/JUlPH++k5QIQ0eblX0jMF43LZQystwPZ7wru47MlvMzM72F7anuToO/NxRX0w+sU0Ad0+PMnp4TvNKx9N8+8v4mK6gn4N+n4Vbt7Svj2EWT61uuNywPx8M5I9UKnP2VAN8ClX/n1FbLaP/42wC8NkLw8v+cQv2rx0GuTd4uu56G62zuZFx1ENmXZp6F3WPqG3TcXAf+o1TsArl8CeooTVOVp7P0JnQHNnn8CkRpBkD+hJ7+Aesd49gsqrlwwlyy7AgT9m1bxox2nfWx+Ns/vGE5Vl32OfR5xJf+NsWZ++9iLEcTunwqHPwYdGPzfAP0zGdlZ6Fe9q14Gfv5RuL9cZroXjGkevqjg3ykyb8q60QddHf2lUZe/weOBYwKK68csb6/V/Wv7H43+41baq/4lf4t5+9dDwQVjCpgrfwgn34/8i1iBQPLSf1L9+1ivSNnLyJur/FQqA3Gtrw2q95x6b8fZFzkMend1WdvOixXYFeRj3/gl6//Z25ztPPbV7n/eU0ba9FXcfeolWMmXRlDOXhu/Ls13QQJR2I5d+W+AUrfmXwULclpTxnX3Buz61vyrYG0nB8vt1zDxvu0n4fin+A2YezEP7LL+WMZhVAP1/a//+T++U4X1oEH6BnVt/fA1NV3U/tZAnDR3k1ulXtxX3SDKXH38I3RNFk/Lb+dVvH8pv+taubhyXt4Lhu/Fj7f9150MkDv89OFec5FxEYHk9MR4H3Kva/lv74Dc6qpH9zL94WkT4zXUp62DvLgswI522vTpMACiuuDwvc9EmrdBXEXQPyFsiD4ScQ396xN8nfDubNuvgEHQazABxSY/MMEFi4u0ry/ARxrbPzyv9npMWhkXqU9d8A3nP0Jg7IEU8pmlaLyfgs7emQKy1YX/q15vgn+jrCjObquxT8VnLYorCFQMsQvCWnVZkl0Ff10Zg1Wxn7kXq+m74iwDPdcBl52NPABr8Ntmxh9PhvQVvD9lRM9F8y+a0b0wfmtIbyF/1ZT+H7agV5bwe43ub7YgEG7/D1nQVbug/L5sqEBC7vm/YES3KPy0LbMHUO6W9AbD2o38vf++ORWJOwWRkSPX0D+m37ahrEKBEYlrFtrM/0BH37aDKh8CO1hLYEUyRCffGzu/jp1P59Phb1f605bmTVRQdRHH1QiCvIScvI5uiq/+DkUTfU6EpMLvt2IA239N4VdC39X3e4je17rruG/IA1V7nAEE344KgXOfxvi+59hgZo/lm7PyfpbU1P1+wtdn/Q5NX6oPqBdN7735XRB/q5bp03V9BOFpmIMyMNr/unL9G6zX6v0Sw/taRdHxw2eQXgrwkAy/qRMQmh8+n1AMG86/OW40u4EED+W3QY6R+WVoDR6+gx1Dh1eo4OE7ULHpdWgNHr4DdYr1Q2MvKsDTt0dOZg+fgYiLbw8bIr1A+3Hot8dho8l1HPZtoSPjJ7zjb0sdmaK3gdj3ZH7DPPx2jJ0MxzdWht+O8jOQfG8DZ7/dPz0/sJu0PwC52fFzEAYG7lWRnfi/1zmpG0b6mul7Rl/sdd699GcPQ+8Oe+PoslN42xN58tpvoL4dd/64FF+L72mP9V7HeP61jrllul7sUB8yMj+tLudMoLgBxcx9nuNf8qBf/2ZZX6gAJAm3jCuXfhCffpOgb8DBMqwH+qW030f+06K+G2zbH8Y9neiA0uEq6l4Pl/2ga314J+teKULk9fzO3xd191vl+8QYKJXD8PXC45fFequAH+srzHvKeYPrp6QIBNQEQPSQfa2s+xPJi7B6+u6C6oX5JGwga7/ui4o3NXnPypMIe9j0yd6DVcJH6FNz1dYTrCc13Sb73h//nRbJT3Dz+XcqQIv3L+yLPhXxtb74miayZu/0Mv1BXdQ9eFACALD+W/P+GupfN+8ob6HLObQdXO8GPAvvLlYwoT+w/gBVIIKkHgTWZI5/O432+iCzjzOwbKpe6gioZu336uuDVg49IA+XCBVX/f49dOHxHqf++N0aEv0WEuyqZ+i+1/e9eP/e4dZ7etpf4L44/3utoW+h/gktsQFUFb4bA9zeh9uVjCvUe/R+Mvbr3vAtKsW/N2/iTZ3vgYW5dpp2EO66PnBJzu+gp1q0+po4v33e/7TjCcA/2heoj4nfVW+F+X30Dz/H6m3z9K3LXc4PLxulXxw4fF6DPui/QnhRpN3LjdivArueGb4L7Z2N/mv1dT1cfHff+M7bffvz5Uboj+7afrkTft+Z/7H92Xe2zH9wb7ZyyzxNe3zpjd1Pl+eX50/PfaAz8m3v6bm8PvStAP7l0Cu7nJX2d5Ci153SpbqqXneCp/L+9BKyk3vdF9IBXJfxzape4QeP3mf5+ZgLAPN+sOvHT31etFR7YPJ9LXW58UMDsp6N7wWCV9z1HN1q9ItAv2I+P+EnXz1+i/dFXtbPcrucVbCXxnvY+2f1r3f95SdOv0AS/BINfXqF5i/jKF8o/oahb7oIHTS954w/6nVfHhT9nNe9d6L0Va8reh8ggB0maVz1CeF6FHjzh+Jv9kzjesL9uz3z6eDzia03HvqSDO+VY7z6+ne5yQ9nTrLPfBADFrg3pfzltHmBfRNPX79frqy9zZ96b8ag+LysWm5V49uU+Vvjwk1dF4pvl1vecv5X/OnNCenPOdPlKBV6edB48yboiX2gij1YD5cuQAaiy8d4D+QFF1n4Zx9oJuMPsUFIaotwizDHwY+41iNaD8ET238lwT8LfFKUvF/y4EGl9JRWDHWMNkPPN3B9e9pmrkBEOK4TiE2yBIbnbUjGVrpe4MSUxiccLWoLjmhXKkMZC82gTizJcpuGIKx47Ww091R7TNUVkWhH3m5NHmwzh+nlyqjGh2J1OG7Z88Ie2Ue4go3xdBTIk4yXnL2/cA7xNES0UTCcz6ewMw3mU9AdIbpKwYhyhhEaW3uOtrA00hlMZzs25vAVPduqpkVxKwI+EVsh084arnU5r632seDhxCRCunzOsKk+Tw051Qdeu1Rw1suZyQFmxis8E/cmKzfZrPWLQnG7sSDrEW7tKaCcE26kstGuPWqnBQ0lFnBJZmUxGp8PuO8rLuIeNwxMbpKayJcwh1RNWW6ZcjPAkMOSWKqDjZpMHEGJKyYMsE6ZrVP1rPoNSWaaIK+WWNZiSS2cOWezF+gSxWL6EG27KSnBS9RayLI4nWfzdld3w1M8hKcLLqPwnAwMdT+NZkYtOfrCWcZK3Qys0K4nJrHG4lNaZfxCmGdb1G9PTt2O4cytwpG43g7dduYrdsNsY4pbi2SQMIiq0IOCFbBjvKsH81gNNs7AdPeNo3K6t5S6gg0OphV7I321Uyg73FkFKSsE6mtLriQ6Jcdm3bhzN4Omy6PRSi3sepvw9vFEW0q6U6sw5/BsyA4MxjmfF+Z6k/rGeZyFg4GEHm2zxSMh0quSw3cI7uuymW3oXOGXzMpqW2ySb2cDMQiK0ZklsvOUWAJZaeXibOWHkbBfZOclUdK5mO/aeE/MWZNUqGEam0Jt4gyV7tyCi+vzeK/u15LuF80gOs/2mHxuhnOpnk7wI7ooI7Pb7kIYju2dmPA8odCTfIOa58m8U0azdml6VVXKiyKguCodT3kHKJTazbSjkBAbMT40y0Y24bqYyYHNhjoe8LyX6S0+nPiitCw5nomjvSOOhZM4HJgcpXWoNnA1Yz+pXc7aliaHjolWoJq6I9v0vKngbbW1t8hhjpvJNDyuCRkLkJ21winT3O/lMHfKZBNIXKCJBVV1G07rGotFlmW54GN6wrmOGpgD1+54BSWHygY7l2uy2XIFLubnoxwegyzLnTNNHluOYCflaMimxHJoD1Yb94DAQbhFuJEmk6Q6jHZb2DOWUeXCq64iuC2HRkPdnysDRzu5JuIROW11OnzciIMB4y3nsXCw9HV66kaMcEQxXY5jcdx6Ijq2soUaUaPhYpZM7a3MmxwpNbCNTnQgM3k7E5lVRvATZzRf5vkaiVBnmyqUpi5OcVIHE6Wc8PtRLhQseho4QqIjC3jpw3alOAXXmsSoANFmA8dJhK4LI3Ojen5o4vEIiweHlsHwI5lbzV7JRvCYIue+oUdU7qhZhY0ESuZEdxYq9m4EL2V4aM+tzRnPkMkxdstwSZN8q87bA6mFCXH0MJXHmt1svz7PI6nuTHzUTrOg7jDUntubbkLvm8zRSD2nVeXQ4dRZJTZdws65cTUrs5GJC+2yrFLXGRTVyTkRBTluDkOimk7CBa5WC72ZI8TIx8mQncsWZ8lN0M+pjcmGF0R8sTmMN6h4craoi2+IuaCiY9ccULG8Nnr6OvSkKcyOZ9yEU4QxXks7fiblc3umL0K5Wg+zcjjaqfSR0JnQm5isIihlC+JGd1ZXp/P0RE4JhsTRE0+ZdssKCr0IiZhQHEAQIbXAO/b2XDF2+GKFWImgL1qcCdUDroAHGY9oIiSa5uDhLGX1LAzxnAnxleNy+mk/TTW0QDcxQ9pYLeZ+3MEmH9mysiYR0hztjhm+6PFFMaWMbVojGWUK4oJO48rEaolJSJPLoa7rxLLYipnIEIqKoWTgejlBrnjOXXiFMdOJKGa4qYk7UyZSaD1KmHA7ZXMZqD1bn8bGsD0O4tWsq7aN6nJ4gRo7dz8cc5qsUEm4t8y52Obkch0FhsQawJ/dfecWdkjLeMosnL2281GQauCDrlRWB7qsZa7s4PkUaMCGE3ppm/EBi2aRxww635Lkcgv0b6xWp3CkhUQhDGWQ9LcGMufcKpnP+Jrh+YUG1LPDO9NkzovpoNjhtjjzB04rBLU+xoUZfh4v8TqNKa/CR4Y/lyekTiEeeVYWBG7gCrdapSnj7nA0FDnJpCi2s7OWQyjGwXglpIfxNMGV1WoQ4BpQlSUBn3H3jIm2eJqTSahzFungRFdbiU6QLDXmbFwRWALFQcJZKiyeVkPDPVn2mT6DTKOdZWopnpkVRkSGUdUms094/OhptLjTWIrANjlaZ0zjcyQXTxTJZNgD2YLCI3SpGjnBxnSXTHJhIo9Ph5gVqd4GdBcR7L1PrJzpWSHszX7KK9RUn5QHU1qxFE0tuLVPr6XwMt4kENjIiG3e2YPW4Ey+3TLGCCZCk4DDllx20UDjdjPBScwCCaOEWLradEKFCQ4TFqOa8wmCTwazWbTKBhjXWTSywqJJwoo4gE2ZAzaZee0ssaY7Vx7Wa7Ik1S2NWiqwz+OYwTfcDB6uUM5y1WXI+USL+4RKLBaNWo1WJBzICSgNSOsYIoTMjZ2pxIX0PHIVUrBQO9nsHMqCaUcvAS0Jt147u8Rwcy3z9o1xBPIbzvecHCcbi1nAEr6w6vluBuYezG6CJFKCbes9agO/iL0ugPPcDIIdvTGE82h1Ii3juGbHHBLwR1c+msNEW4DsBWimrUE3xekJM639FlvAgTnLfecg+Vi69oXRCUc0DIZpbnayWkdlmPkCxQYlVoC6YTMZLZAdrsanENuQ6jna6DTqtDtXGYiVw6l2qBOUbhgMtpSPmVLNZ1LKpLmzQEbLRRa1OqVOljsJZg81CtPHTs7UldJtjaiTQnqm+g55cuRxl2rp1Knm9CFrFjsHKawFv5aImdn4dSsdq6zMgAQPeI4FPsJra46s5p2xEx0sbNJGyMf8kT7PE5cY79H9lkdXpGPIpxgdtmvkuPQodOmMRih/9Ah0LsInLfeovc75AUytliM4Gs26VFkrrYXkBA2fydEQ3e0QuRHgHS1jO4TTTVtVeBFxmHnKnBBXlozJhD3J6tRkiTSLlW4mkfYx3elrdWkZGH5SwPq1RbARJUaR7SguhZ69RhsZK26Z2/TQqYYbZYoyK1My7LNrbCKOiEx/RA6HOKGHzGqMjL3j7BzjAbXUj1OJptxdZyyMQ6pN0IE+5ac+AephfjUq1Ym5y12XHe3R2YKFDbWZ+5tOEuSgPiRozS+n+U7AxfEua9f6Bos0KRHaaVryKapOItvCDoY/3g+xdpIPPSmXCINHDv4uPMLOrjlukElIUegcgSvT3fHJqEK2w/hsTOLGHJ7C4wL4be0gIjdZBfCE0lfBhhGk+TRSpA3HR8FkOGtmxYRumIqInONCshanxXCmgojKzrfZNJidFwa84cm1ukt4qjnhmOA2o5WwY2KfOaxzVapHeKiAVqyctrSPylRBe3xhE3gcGPEotybBbLw64Xa4xvVSCAn4rCQIb8YKzSSWlMGDbEDUHD0YuAxrkYbCgeJliqQlJjUKHe9Q3GEGCh5Ec+1AkFvRA8X/ZGXPi023ny3pkwsfMn6Dl1Npud2KfHkqWsw74yVNSDhHCNvap6zYbdnUtJFdPpdyLqtMWhZiTBgE9FwoSZqniQPL4DucybU9iTOsM+bxOJEsWidEzlVAqLX1cUj0wWhIaDQZjQuMcr244QyQriTaICyOBMWixlAbS6mPU2ThpmG+wquMrgmLJQlFogpSSztkMqF5cz6qTKaVRKJZYZ1m+0KWg9yKnjlWq8DSLcuQrXxwIzedGK0v81ydItPWUOYTz5sl2AE2j1RoUyEdVovtUS+MKqD0VonFySBWBZDAQMGraHIsjjykKkI2F2m9Bl7baN18pM4GkyjbtNzRzV3HpdebQ6ltCbkSNly03Y4PFuLJe2GSntOzULiYfzrCLqsqnZCd2NMqSs7RaY0sc+cgKxJYX4XHall24Zx2QLBXZKeeRsQEDrQqBjFrHeh0CPxtzG2MlQOqkxJteYk9WK19tFdrSklX+bnbV4VFjtd6Vi3wbMExLT41aanc0BW+GRdVgQ7Py61rtabficyM41cYPis9bDrzu/1wsZiqbnNoDI5rpgimupaCVKNZbfBRNgKLppDCy6XjHjbJOjyhirxX8rydRnpoWzvb29b8eXuM57NaPhc74bQfzjWttmnBxfGFvTWM4XgcGryl2dlORRMJPzLd2d8M+WUGcsx4tKtiRMLzRW7nSV2VG74dbFe2t15Q8dlhkk6aWji13KyjYQXKJHhTizs9XkUgi65mcO5PQz00qMlgjmxY+aQa8wafkchmJVYIIra4hOYrxjl4i8GKlXEGmQrDJX4fl2yPaKqj4iYenvXT3MetxaDiMnWC6v4kEQNajKiqoMYFHydGcNzEerI+SS5TIGdhfWjnMKVOs1xKSxtm8XBM+7uRyatiSU2QiZfGQ2vF8epJqfxK2xxBWQpydLblM8ZFeetYx2NKIlaW5OE80TjOUOcMrOmKo9xUCdzAJIe5CDs5Ho++pdZ0mgpjZNDysbae4+HathpuZzV1IA/Opyo8GQoqTBb04OCatLicAlRMY+d2bLiBtzRgY6bZOWYnRGvKcuocBlUH09OoGM5XU5Jqp9TOyrxmVCuDJk4DLZqF7oxWMrMSuKRM50dRNUU3JSNrtNWTcj50+TjenbvkaHUkvxyYzU6JlizDWXjo1DpamGfdPXK1SReHWcuu3cZpFxPBWpvjNtHi9fZMh9qUrQmtXqo4u7OXYjYg0eMcS8ITWNgLS2Zxrm1GQ9FghGoHdIWKJb4WNpO9aGu7c4QSsyrR+PP4eJTOW6mcHIa1vnY8djMb0Ed+V8dYjceN6yhwM6ylDUJPp2lnrNFqSrWsuqpE1x3MhmHaLMT5eCMJ02wTZbooONhJtYYbB8fWwSI9DjKzYaUIH4XKnilBucBmm2x1jFCJywcz7GhhQlPXYCHa585FycIEOsOQLsHOTi7iuwjO24U7CinwbNA8ysOIzzNJvjsK2bDkEVaKbadBi/NgDHu1wwu+EldBg4zWGIoKCqh3DR21U5zCCM0LkOWOgO0Yo4gDxS+4WPUPzDoYz4mcAevGEKw8fWQxIuS9NkMorQrxenHeIMtsdJyH+JLhGV/JSWrTHAOXpfjzXlFtixlP6KMzOKhnvxRG4lYTErpSXBENg9NKU+HWR3fl3Jq5emVieMstnd3U4BZYNZa2GzQztB1+4KajBaXwNABELJTjqNgeGWw+GcKuZvr1DlmGPq9vHfyAhBkVVvYCkZGRXIE44KU0h0fJ3FxaHozaCqhwZwnImUbTeFWzHy0rm3QUPZ2j2T5kpS4DgSPvSGXlpaYmcgQooduxbkX7mmFxdUzw3txF5IoKtJju9yw4RZ4J6rQcIYc1GRrIAMa0jdmixXSUE8yK9Bt/NFZEHtX2XV6s9C4YBfIcpz3xMEnA0nRankZEdbKSbq2hA20wPA0rSpTT6qyzyLgeTg0Y4S2SWk/o1BU24jkYj4vdZEWbgj47jGa+R0pbNQRGSree6hzlFl3uN7tpcvTispHkRhEDdhyrccsvt6HFniI3kxByrI/1gDiMYX8ojSxEEyYRtZnjZkklO/lUOeolSp9lrTUH28OGytCucGfamR+SZNzqxjI2U4oAC0QeQ5QAHfKb4X7obTAZn7aiilvH42ZmelOGw9rRtllM8mLKarPTuF4cYgExt7mKjo5DZUiHOWmYa7SYHy1PSucZCPIez3uVbB/LXTrxFYEJ3WllC/Tg6J2wyapzJX9DeX4V+A0sIZSxtE/GmZyfxc0ED5NlnJxJrmTFms0kf5GK5Ajz8mVT1gqQjcYjBsMZzXaGBZ6GLMLFlFMGRzmbEWxrm0ZpOANGGuSJFHRoOjznqDNbdvuiI/zjAPOHS70IdA0VRtGWOKmU705hkrdWhKyGYL1nV6kMO8gxJ+yEzd2xjgTHiEZZcqKD/nmiMiPpcEYR3DlhSUC7pyCgeMeKz/WkXM4xbG2og/N4wg+0utkYJcodKNFnVESxbDJQu8nKYEaetFfhJqnHXHrAJ9O8REiCYbdgLaQPm5pgV4ZK01HK4Op6ARZ6BufwBk40itluDcKxhGNZYFsYxrHFLqnakUKM+h1uHKdTRkvWjbInybcvoU0ufxog8vsXi67fnq46FM9HU3zs+tnlvO5+HOX2V3Rv+/1Ruqv6Y7q+7fFyg/f5LVLbTcIybzLv+uoZ9F+u5492Vt+29wVWg57g3zfznx76t10v7zxB/3T/BaHIcAbxfp7ZpZdDi8uRxBdTZL/cx9XlZf64AoyVvtNBYQkQ9tcxgtK/3Cx2I7sM/Q/9zYv+b2oUflmBCblTX+9QQzbkAtR3oGDG5TpMlQd1a5c+mORBgPfcjS8XOLzcbfZ+Vt8uK8epX0H/7O8/PaxvMx7+9eF6z89O71Dj7HJH6mnI/Z5f/75iGbs9rA9gkJs2l1vvT91pvI9vmPrpF/k8CwIgaSrAWU//h/4mdRz0n/6F3aJx0riKPvS3eQAKp6lBY9U3XhTwoecLzsv+TadnMgGkGPBzkcEztZexPbaiF3h9E+HlxlAb5fvXnMXP9AVNmQESbtcecyDSCwW7/o717XZekKdp3vYs96/TXP7YSfXxS03399RsJz/6F16vZpLlNWDlSlqvsOLZGm5dVWRfL99cBXu9BWW/w27Zk1X1lhrbKdQbbU/HWzH88Q5dSxpaS4xm4ioNsWtIViWj36aBHvA1+P7wATJZbSnpGgRGqLioWZDEQLhoQRwrUh8geiOr9HoNSeodJCvIPEuDPlYkeZ1ixQVEgPmiBHyHBR4EgGvSBfENJEuve6ACrZJL8BUnWJ7VrA93gAyriT0ORlIhHJJxVWNJncdVSNZVWVrTgBwKgBdZkVEBNlqgRe0PgB20QbQBvkDrJc7zPco7TFwHXKk93RApyZbKLpYatJR4igaNBA0oxQmevqIEzJI8zgofIAoX8AV9mSUBaM8898OvVEPmku67evw4+E9qrCT27JGSqKng6wfAvardQZjsmv4A4Sq77gXFqJLwzHgvdjBTugAD80X6Cq1XyWvNgSH9d31N3wFDFI3zAOa6n/yS9adJd2v4BPfB8Ped0t6OwO2nuOrmaV5+hP4RBMGrkApFpR+AiFzXRfURhr3rkaldFH+4+R6Os2Nc+/CosRNxLzxAdR8E638//DcntbPkfgRd+um/H/pXkgO/LPu32FZ5/yJvU1xub6z98thflbFvJ/E/cIfjV8kP4zq1nQvpqZ+Hp3kJvzwE/nEGjLgCIWqdNyWIAKpf5OBr3t/L+b/PxD/irC5zr7mE++dbAG8Y+4IjCmTB/mXx38/Aw3eRPxH5U3zCoDBw4OtNSPjiuCwIYSBe/LHv/yRCnl3zUV5W7zH1xXWD967UXTuvv/83RXB22Q==`;

    /**
     * @desc These contain all libraries that will be loaded dynamically in the current JS VM.
     * @type {LibraryDefinition}
     */
    const EXTERNAL_LIBRARIES = {
        'currify.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"eNqdU11v2yAU/SvEmlJQiZW8htJoWrunrX1ZnyyrdWycMBHwMG4WOfz3QfBH22VSuxe4xvfj3HvOnZSNzA1XEkrU8hJGav2T5Sai1BwqpkrAfldKm3o6jRpZsJJLVkST/udOFY1gKFxx50olRISJmgGfr88/ZgxZptNwx9muQMGESYplCG0FM4ARyOi5snsuC7VfhWt5zmMj1DoTq3Cd9aiZKFf+WJotr1GcN1rz8uDBWwuHqaBWM9NoCfoXICHDGhvUDi8Klrg5TW+ikzINFjtZz5kGOT0zBM1+NVy7KXQG8THNdJqjrl7ukk7myL/z/o13bz6roJLtwa3WSsOnL5mUygDXYtFxAi4+taW9eELEbLXaAxHnqnDT/H5/8/Dt9vHu/sfj1/uHu5sIC+vTVdRDp23H4bK1lvgWknka55kQsOrpxS8V0wFT8OS7SBOZHo8SWVzhMUDiMDHbeftK/c9Tcf6uCZWuUy8LSedEXplYMLkxWyIvL5GCxlVGpIdjYdvxuUxGuB4GaqPGKbM2mjuVk1G0L/l13LpaHpmmmd40OyZN3dXDhn7WOjtAfb1Y6dliOUdY0QVRV5ooB8UkarZIx7BEpZ7Dt2s29DsIUqLAVKA0KiWot6oRBVizQXyTCFkHD/fNX1PWWb1E3D5VlTjAZ8ULMHdDJ2HAfwtavvZMmCNayTwz0OBTh3GllVEeXVwLnrOgg6ExhBzN5QBg1mOaLciblRmFMpLB/oVjzG9HpZ2I+5i/39CPRmD1PzGYvyMqtW6Nne6PR24tbt23O3ASdTKNUgQHG1lE/gAIVgDf"},
            'curve25519.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'openpgp.js': {"requiresNode":true,"requiresBrowser":true,"minify":false,"code":"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"},
            'scrypt.js': {"requiresNode":true,"requiresBrowser":false,"minify":false,"code":"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"},
            'sha3.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sidh.js': {"requiresNode":false,"requiresBrowser":true,"minify":false,"code":"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"},
            'sjcl.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"eNq1fQl72zbW7l+R9bQqaUIySVG7YX/Zmsk0aXKzdNpR5RmaoiwmMqmSVJZa+n77fQ8AktCWuHPntolIgMDBwcHZABwg9VUW1rI8jYK8PjqZreIgj5LYMO8WYV7L+V0QLedhOrzbsLmfzen5IfwSfg7mfnwTUvI2mcpnlAX0DJAWLygULgnY8C5I0nS1zI3cvMvnUdbKkzdoMb7hWntpmK/S+N+PXr5+/e7V22HtO1n0Nswy/ybc/HvD9DTPNyyKP/qLaHofqM9+/uXB82eP7wP1enVzH4gP3z29D7Q4yV+H/vTLfUD+/PJt7fWTB49/uwfgzWZUAKiFRsgilpp30czwTjiPWoswvsnnZj5Pk0+1OPxUy1vlaLQKstXVS80Ps9r1Igk+1LLoz7BujmjoEx62rsfphGU8GtuTqwQ/LMZ7etkeOpR2JsxH2qV3dzKKxDdn2KZ0eyKABGzOFmzKljxROJ15TZfNuMdWfGwz8f9kFHIjQHMZmjPRjKh6ywNq4Qse7oTd4NGesGs8vMlolqTGlNuj6flyNLUsE5XH2cXFhetNrm7H8cWF0224nc7k6svYv7joy/ebMR6NiLCbTdgcVeKyiq9XiXaqZKKKBWQWqOSXlSK9UrZTKZaVgHqESlFZKdMrxTuVfFkJHZ1ZIFHGA1B8Diovyi57F1PR5RWNQ6M5HU4n/Lro/Pm5611dawQ4P3e6yCiJcH7eR7Kig2VNWMAztBSjJZ/GE/gGI8mQtdWm5LHIyFkolQJYjSWokrd+RKW8dY1qGXEHINGQzfFwiVgZDdkUD28CDsjGHfQLj+4Eg5+Ne3IcI3Sq611Eowi9croX0WVKBJsMDfG0nIaDeol890SCPjjUBW6k6Hjvin6dvni0r1JQoUO/jmdaRkKfelfiMZAP+yrBx474bZuWgmVRAwOCv7ZNNJFaK8uYonz3in4dRzwAeQr4XfHr0G8Pjcyupg1jeTUzTSsG6ujeDD1dotNT9H9hpWsb5JiDMgFolVoG2N03G/OrRcMIruaoZgQE/Ip+nbZ4uEidn7dt+gXm9Guba3tElBbktnxAJYILqluBSLkTQXxrLlLtiRgDayFS3kQMhTUVqc5EjIi1FKnuRAyMNROp3kSMj7Va2xUHpKRlJAdg/DHuqR9Pk9vWT+OQlMRYDmdai+JaYiYtWIuXn+JXabIM0/yLkZqNRtZarrK5kZCYy8IY+/Q8U6phlIIDSAcYkVk1m0jGq6/iaTiL4nBaP+H5l2WYzGqfIiDwqdGQzxYaAtBbPw7CRqNeAKjz7eJ6sVacfLrMW/50+iTOgekX43AZw2Qhqy8Sf5pHt1CQw606BinYx34emi3o01X4crZbvupNZqAvUKw8xksrSOLAzw16R43Wcy5VtTS5LahlA0W12jFZESIcDUIotAG6auStOcaAy4flYAhP5Ls5CkHSQprz1vNWGAfpFzLErbkG15c0VuU0wxS2/OVyAePF/PRmdRvGeWZuNjqGlRkLlYEj3pR/1muR8dKQFkXpDdIZZTmPbIhKOqRBnJEyYlAMYWHHGo0umbVGo0+Pv2LW4KsURo3oJlq65mMybtkiCkIDsk68O2Ehj0bhuXcaWW5fkC3lyThsAinD5jz8Plqv+1wg4YkkkAL/xuNUU70ipatekVGp3lioXthUCVFASOmDBEJC7nogAgn7ldtvn5Ja6JlgjoQGmPCB3k5LvRmS0mRhsymQbTeiy3AYNkHTDFqIexc8XK890qhDn4hdIju58kHtsY4uZbkqq1/mtClH4jyBC6KNe2uZJnlCksXvSqYqWSgUlGY5s80Ngzt47LODz9lwPB5PmPYHf3cyJuxl4ZEy4etIRqp4R1ifio/m3CfWWgh3ASp4TAZIaagchHM73Yt8lGOUl2NjOs4hPCXJc0HyK8oT5cEYqHFC8jQKr3i6XjuwkUtQGG8mlcg4/kRXEYHAj0s/bfrxTBDzSvgQV4MBE1KascU4m/AQYuB0+17btgenRsKBBP6m+Buiu+ZVt9Np905zVO6dpleqZP80hOalrClgVLkgpVAGsks++iPYhSeCK8no9VlAuWg45rHkVcotCdLR6nL6qcSDKvJAz9oQK1xH+YM09b/wO7y9oS9D5YbyC9CsKtD6ziiELTpruyZru02j7TQi01TZjsk+JhBYSAVPwcJa3WDh3y4BN21GpCI/56kf5IZgAmWK+As/n7dmiwQ9aUI+Gm2n0HhGs+02jNCKms5VaF7m4xDtr22IIlBIr2Sa9OUEtEiH5XdKmQ3DOT+PzKZDMxqhpkWb0E6EZqGa1mtKlQ53wd+FZo+k5iOHpahBGiXRyXMT5q/8NI/8BYxkoavbLsAmlxqg4RZFIwiAvU5ZqcZYBd+EUKHoc5E0CqetRLloQiB+aQ/b7qkBCpnWYZzgFgFlgCyGQhIBtQqAoFLRb9VbjH+FmBifIIwWcvgx6tt4RA3edph9njYapBHDcYr2dAItFSYRk98aruP1vH676/UvLoActAhYY8NUuaFiD34hiJiDoQz0cw3VKAY+Ny3HHgw6jtN1e71e9zRnVXeHOb8QCKcJHA4jP9sqaq7XbZeFf6yILooQGqI60WGoDn4BG8t+nzijwpWyNWco1J2hZA3GSSdXmFhN9GFLNuw7Q+lBObyZAFFKUQJCJlB45qjtnsOwRU0O0ifS/0rJvbVHipPLwUsKXgulrcxQJqvwyQgfBWCN6RZJSWQKXzyTEhUVKGYlr11u8f0QXHqE8zOYOAn80MBbIaQaeuMcbzBmKJks4WPRuIMUkRhxjPc4p4lqSMYghxXAm0NvLr259NamtzasyfWXPMw++csXZJSEM8UipexhVc/zotOWFZoRz8nDpR8u53FrevQb3Y7bt9eGeECbwY6vSft7pb8l9KRYDmmt8llfzfvvZmly+zDKM0OfT/F6XUypDjJTafCj8+ysL2ZKGDoDBl96IZDRM28CYlhcNtKiNh7N/fQRWheTpH7xF0N2fs77BZJADkXevX72KLldJjE8PAPmXGYZCamSPCmQDfkqDrPAX4ZVGa2aWbp5ZG8LtpZol2xEuAvD1F9DuSkMH5CCY22tS2qmYBKYSimSgkiPskn/VFSHSKCPGu3n4eeDRAfJj2GYWtywP8/s6j/LgAaBzYf6KlZwDKcLC7a6zvLU8Eok0yLLZkdG88zbomrFAsUUSurPNFwufGjQs9+ztf357IbV66XuZKHF6wVqdbbXA94vZNW+Anmy8BkNUIFZxMAFQF6bGewY3IR5p6mp0fDaz0Ko07uHw/qDh48eP/nx6d+e/f2n5y9+fvnq/7x+8/bdL//49bd/um2v0+3V2a/Duu3IRH9wuHidPXz29g1sD3v44M2TYYe9fvLiwbOfn/38dOj2WDVYcl1Lrkdt49KiikJktnJLOPCvIFI+t+EYppc7pX4d7gKDy0hz9K8JICnNWNH4NDlfjMzY4oFgYjCwMb8iXQ0R8+H1XUCh+efJpTEXGvz8PGn6zLfg/ZFeHxpzyGDC/CZPJOxRr1GAbjROIgG6zuvFAMUVw5DZ2WUPLrkDnPluianrI/RJzbmKlZrtzoL0YuVmn57+cXoGJNWSStE96DlFySVK1mUOhLA+VO/1Y/ZOeFcXsFwLzOam4WfMpMOCvik8B1HgBBPA9Mtdybp6u2ilVUrWBsYsmJOG33xjxkgTh1qUxT/ktbq1tOonmLLPL3yMXpP7LJCSNBWO9NxEz6C+subcHE6v5Ksxt3hsbhRKnW4Dgxgc1VP0nU2F9Qr2RGxLWQmPGoZth7hb4gHnWfZ4GO4VLHmG5ln6t673DVH2r4NpOLuZR+8/LG7jZPlHmuWrj58+f/mzkmzrrH5EUoUts3dYrOuBK6Q8flXKoP5j/u/v7uJKkXZdc9P817+l39I9LdaSz4ORCZMXlyLoFyKYkQi6XZN1L7JLw1cy2G1mLLO421VC6EMIuyxr8q4SwnYj2RLCZEsIk3sJoSZ2Y1owt3dkSpAhKIwjOutzf6unVr35r7rs6jHx8I+Ix/3ZXGICPh+53fP40oibRBa1QBcITo/BnsTe8OxicxhcqXcDmqmr83pcLuwd5vWYBYLXs80uD67ShcbrO+wLOmnM5RzncxQ8zOfk4x3ztsaT/4K3pbxh4RPuuFXJAQt/T6+IFpD/+64Qbd61srnvdrrVkl2xJ3W9tVjH8ku5UPYjLfFXCwEi7wHyHuzkkdlcYIJK72mYhblh7jQp3reWCtUMXfKqVtJsrZZTPw9peXQWxWDcP8N9cNrik9i4eoNSw47jMtV8aR1UN+jx215PMB4Kf1u8bFjZ9l09Ez5etXpMC60h3/fnK3tTij4vKVW5VXJqJT9gskKzr1SWW7CBbfecwcDtYFqL6aZzTg1JxFLrCJN+U9gf+XGc5DWiWu02SUPQwo9r7lWnXWvWnBpgZXWBxqGV9XdRnLdd0WqxEUwNadnEkFk5cwXprbRpiEcD02Xw6TkPobToixmp5T5Sc76o7HRPM3igp0ZmObS8Ca3sjJJWtlRrBvTd3ISLLKz9hQa2AGjerRjaipnUhC89Pj7jAyJFGoiEXo7Mj2q2mCoJttyR02mEcuFYed7KnsmUtkolh/bMcwfeoNtzB10SUlVHCuECuBeqoehcerxzhdDRZPi3Ibj6mn5oxbRc4ddXX6uGT428qSNmmrThU+wvkEWHZCTcpQ26dJSQCZLK64Rm8u4oPA3hxopOy9WE5HuIDj47o+s09D9syL71L8ikSxGEGea5pMUy+YRpRqtDw6+U0O5H56xNpAH0zZYOw5B/VYf9oekwEtlwR/KnyJvu5JFTEhzXYWjynjqM+PGbOozAHdRhju16B5WY0gjRXlcKJRb8N5UYjXxJqoNCMmWloZTNM4VhwKNjOgvzVOqfFTWa9IQB5LSDITJNUTk2NDanxcJvyHB0HL2vyLDqW1gs7xcy7I3ajpLhaEuGyxTbe9uV62BbrqMtuQ6gcEu5Vh2Ojne4lOuUFrkw0G+HY3jfPdfFvNlpu33H7rfZoNd1+50BcwaO17Xx7Dh2t9cdMNgSe+A4zGujWNthfbfbdeyOUg+/DMdId22njxrd/sDpdljH7jqeC5B22+v2Peb1ut4Az3bfHnTa0Dudfq83YD0H+T2gMOg5/S7rtbv9bhtgULYHOCjX6/QG+IJqXQcYOF7fbgMjp2173bbbYdQeWkXLfafdbtus4/R7toeWXXfQ81DSaTsu3hk62e/2esyxB+2e1+ugNy51iEp0Op7Duj3PGaB3joPWQHS07nX6ttejbnW7Ah8HzfY78K4HfSDJABf/sYHX6fXwtd3reX3PY7C/aAvdAjm7ttdhKC0I6KCS1+6ipyjWcaGAO51et2+jgx3CnprqDTo2YHjtdq8LSjpdd+CAB1iH9nHgmBCNPQd1gZPrASmgDbJSa+jNgIC2+07XRs/QPRAL+KFJD8RybNAbzaGEM8AIgAbugKCybsejdoAgmgDRCQ8C5hEToHtE4F7P7YDAXWrf7TMMaAfdAObdPkhNQwLnA62A6m570AEVnE6baro0UuAvWmy3QRvWc7vIINjtzqAt0EHzPQwFSjoD0McBPVwQDBLgCsra4EWXGnFdEABVkTFATzwbDOEQMTqO10Y+MvoDDx/Qi67dm7A//lPrVQVFVXW21/v3qtF256ZQe9Lg5UMxIezb23bPHUWnEZm8SDN5kQnNk0fxCj7WSLN20dg9PWTvWPXVciY83P1Oa8hSX7ylSInCOu4Dk/ax+rwHTRSowP1C4VwwpzCmsbbwLTyh0qwoByek+ZGAjDmsiP3yeSK36Cnai81pw5l2WBO5w5pQdM8Sjy4F+STjHkXBJOP+hN3iMaBALlS3KZILT4dCufAEoE/0BKSP9ASoB/QErIc8Zh+4z57zgH3mc/aIL9gTPmVv+JK95zP2gq/Ya37LnvEv7BW/YS/5NXvHP7E/+Uf2lj8odzYxhHJrk2bPTvciN+G1gVo5RWaJF5BtRK7mnUyDPZyOSQEBhvFUy0Ex0LLtiNV/x7wyngrKir0A84oePRU4Z0Si3FNVTmwKiFRfpToi1YM1KOC75mT00U9rT9Ho4ypTtum0ZZsDWb29fkxTzoFstMseiwYdmS0KPaZCkSokWuyKj12T/VwA76GL35Xd6yL1i5YSNOGh9bNlgO0Tq6xEGAGSfU5LBPalMwTLhBZ/SuUs/lh+e7z17Tv57Rf57Zfy20YOAw/XELpiJHhEqZ/5i8azq/990XgpqPIHf914dfW/rxvv2G8c9HnYeH71sPHo6nnjEfvQ+Hz1ofHk6nPjicl+4sZ33Phwfu6tH1L3ieAPKYpq/YGSMgXyfxDkR48p7cmPVPaDKPtQlf0gyj6UZTOBrMl+5ZlClf3I/0TXXoP2/fULor2HSpT0ZJIgvgCM9vo1kgMK8wJHvcXvC1HndVHnhajzuqjzWtR5IetIqr0tqTb6k78Eg78Dwz8Dw7+CALyAALyGQLyxjB+5+GNxGrinFv9DVv+jrA4cfpKffpWffq0+4VsoUHxqRWtbfo62Phuv+XvrafHtffltbUMuH0Eun0BOn0NOP0NuH0JuP0COfwRYMMFjwUq/WL/t8gHB/aC3+VSDu5Fqh/vWBzRCiojH1kPL8EXJDzoGUiXxufVZlHQnPLCeW8ZclPysl5Tqik+tJ6KkN+EL65GM9rPPn+glpSrjM+u9KNmd8KUFMs/2+y/VHL+1XouS/QlfWS8s41aUfK2XVBqQ31ivRFFoRf7FemYZN6LsK72s0o78k/VOlkWvrq2XlvFJlH2nl1Wakz+w3sqy6NdHCyz6YIeFQFWajFDgdisIbvld7N+Gwzpe6+wp+YaLKMtDit27gQcqlrCq0q2n0qUNMaFZxc/3Sjbl8oVevlyshKltbH1Rrq9cuJv5+mLZdjlRTF+ZS7XNLsdMx9FEYFSEIpVBQhIgRQppUyd9BZqCMrVZSmqe9SluSMvyTVoFnBkZz9ZrODEJT9ZrUKl38c0Ia2A/rEUfa7erLK9dhzU/ry1CH++9mlieVGFpMRwL7yJuNBZkJE7jUayF7cXnTqc5F6vi9ELTl0Bt06Wsf2ogM6aZhk6xXwwtSsoUK9Dlt0f45uNbJL8FxbzJb2Ha6DO/lfs3WtSWRskdAghrF+uk9Hm8S8pgKysyQe5YYR+xoJmZILYo8UZGCIk8onbADXoFiN6F/1+icyToHDUagaCzjDmmxiKisQ8aR0Rjn2gc79CY4o/mu3ScgzQL0BH9CnfpP5f0lIOAAidxS0aOzInCmD4f6VRxVkJ2CkVr0yQUi/a3tJ9VLxlDNgBfzt8abcHwPq0L7LF5RH1N+DioFoqZUcxIL7se6Yak6cL8rOMmpsoMhUv+SFhqmlCwa55ROHYZSprQLFfFPxGRux23N7jgRrolRBFG0rz09bYxCUrNybB06DsXPBX7IWWT24UpJM4DUuQUE09XnEvklWrB19SCZ+poztEBv4hDY5HlleG38hwCYJra6v0vh2iqkTOgTRgip5Gd8b75vUuRlhAPp3ue3Y9bVZQqDbDEWS7HVuQ4T8ogMy3zG4c76PSKbCDwiWemob+ofYryec17Gj2sJalcDCbOqRfb2hrjCl7CSKPX/s7okbKg7YukRAEzIxA51YgcQFwKPZuw5KtE9jUBy6BwHh2g+BYLj3zBwvRhXi7a7OjqiLZn52cd2nueykX2Q9yEzgj+TvfwK8PWPOptUGkmHx2qOgpRQHlor5Mi6O8OAzlMGBEWJnQjSOuDXP75fOQTnfyLqYjVLmkNe+ef0X6yxZfQOBSob7GM642waOxPruTpCrzC6bySZywo4YqEKxNtkWgXYWI6NkGpbxdqIVWgkATXbmH66b2+bzxpHGjW5PaPhbOl39yHAGhdMwNWsfdQjXCJT+uN0LGllC34vBVR/G55VAjjaWwNgwCzhKOmomcK61wYKzEGllcxrRiMKV8YdCypYFYKzvAwpjM+KzhiYaTagFNqSXusZH61QE0NBOmguUabJSmpbQiqHxRGxCQKC8NYopYcoYWx3OVHRmBN80A2QdChE6yUBXInmFUb2YZsKL5Mhjqll7d+QLJOhcs+z4uXJStwmoLLzUP+wP9f5lDDVzBJZXoVm+ihOkRKsMmyYhOM43ybTdjqWDxmM4PvvsM8YvMdTLM6a7u0yeSZUCcgio/fGbiiIAalivFPWUosRPS85belbTIFLjPl06yabfc0ZRU0nUMImupCQByyKAS3aAHe2gGFCmg6jCUjONTkDh/IRr/GBycL5aIULS9JxS1092xlftNvAdiv+i0lbYpWML7EYQqTrTNG+pDrG/Ys5hmG3NeGPNCoUOZKEwcn1AhYYiRGICVYjm5UBVdghANOn8mHBUIVKKq5N8RlsB/Xxgbce5FtsT+IXjQdiHazoutQBc0qjLlAtmg9NbcQSIwShhD8DXtDccoi3JXOHFCwKx19c0TYq8xxyxxX5bTLnLbIcdqdU4NAiGxzUhqGm2pKeENTwmNzKm1GVcZy60NUCFPpGd8Ir5n2DlksnQz4S26f/Mci9Fj6zOHxOchuy2zPK6sGIDalvyvRkPM3au+cB5fw9P2Kr2M5FYm382yRaw5Rlo5HjifmXl+cqi8QH1+Jj8Cf1PY3JOXmGx5+qDz8D/6WXMijL9txVJGK2a7kYYtKxPLEn6kMJKKyIIx9wo1wrC2GpxShP2k4tH7ZTL+nDSnwcAaLR+qeiE1VnEYMHiL/qD2yz5NR0mya8TiZcPqhRay1KJI01YrpKJZcxh1GcyxKXfFmx7XtQbs7qIKJsg17vxVIBpEv5/ly/hbpC9Xki2bSCRVHlHnlJjdSoALHyNnLtYT35O7nC0eqvZ/fnlRzaxp1DEZEm58Fyx/zXIujz2zGVrAImh9LXVmWPYN9uN3SGjBVekZC6xV6BoWWghD7uo4NupwTb4PT9eNtpcLNGAhCDJ3pHXoPjVOxTWayva+Z/K4xytY2J9MoJgxXcBx8Qm5Lpo9iUCXC9dpIdusGNO+EvbdHi/PlaCG8N+krzzUqTMmDXmD05uQr41X4ynPylSnhioQrE22RKH1laPHbci4yAxbi8MRBLEKuS8vqGBFWOqlmx0rNJmyvGcwxzK1+0cEIwduiX8m47FUyLvuUjIseMeH331ZKLAHVMW8T84BUOf9RFrTmsLVaLAMpF7Hb8w8OGVuvt6KtyrCmsTqdlwG/MnqhVQYvkK9UHrL8xMek9iImfifl8aSLTIQgRKIBce5VHQKWB17omGI64QN70HFdr98VAZ2i25TtdLxBhzYu+yJ/JFtCnSLgguqrHbFPqFNlO0X2axHIFBllVXOLJlq/1Ajww1+36SdPAhFI/5trVQpujc7dLlK6G6Im0ZzWqA3M2xeLcHpS3w4FKIM6VNxHdBNmuVjyPIyfCB3Q75jQei9HWiMBU6jzE+cYPNn+ftgNVbIVaQsk86NYSbT53i0j+1hhwEpwEngV/KFH1RyMl8jL9pfXH6Yzd4vTC09CLA7Qac7QY/YFfAT7Ir3v0eKln/q3WS1ParIBDNZ/EmvD9ipFYg3yeCVxCpLIJb0ZjcomRa6qtW5pfGgJcLprd+bcGWEKsihCqI2ETrGO5oVXkPFYn02U5w/ZeC79U2fkn6eYRFumXLnWHFVTxDUH58VJhlEgDvQHUE4xfkcLTNMKS1QafTqqtuDTYgYsQlYXNH7LVL8kpThdHki9sqWgVAQUZnG2en2lgqFaf+N36uqUn4usd2XWP+UO90w+1Mb33C8KXpfOFCvNlyyieVki4zmXJ+9k6gUP5ctjyJN8+4nfLdUeCd2Mk4XhNJziTSGykk3flE0/46ri37mrwrt8TuufXZl6Sxh4FM3BKOLF7TNn4DKQgrX7HqNA2F4XebbrKQynPm+Dz2W/fN63CwrrYWjyQod/JOk02/Y3aTVZrHWqyKkok3fagBvphKXowhHRKe+/qd+EcZj6eZKqEHRJBLnomTZkb827lJ8UqWemPBNVhHrZlXX5pwhJ4IduXrBUfxkd5XO6FzKeS8Vqa8Ej8pSn6LFhrlWglzr+JwheTZwxg9gKLgvG4URXRyyyJBFuxUHB4o12tdfrE1nnFTnVFF4nbmQoO/IKTvH5XoMqLVDej5BWLRSRaCo9a9LdLReSlQsYCY/U51fwlxRX70dmq3sRypX+AuaBCylkSWm1vSrWZS6CN4s3dQdFkTSFbR9ttFM/cspNYfWp5ZjfKxZvNGQDNPCxevOLS0OU+yMcH+HylLo/K4uWh6HpXoEwfxzO/NWCDpn6cRL52ye4G436mzDPoVyFOqcC3K59ihaLWrqK4tqXZJWCSYNVGuVfRjW6Jisiq734QjHJtRyGjFT3fW6k+G+0Y44K5bJh2uUjZNAS805Mcuuom9aFvMjLEQ7eTKLuSfgbTZDm2/Is3ezsU0TnpsrDxIaKBHqHGnI6WCYLlYnhrY7wB2LZo2yEF7GqImGUr9W4FxOhwnCad4GfhfV4dXuN/gxLwNI4OkXELkxK4SKMM6XkweUOKOLj117TBSgiDnkk4CXX78Mgrw8p5n0sE3pE+6ROfU34S/FFc1qK854t8sxE6P2dNH3qPEdSneOgULFY7Y8TtUaw1VUYe9mqau9EHtReUJe2ATUaJwsBrCBCGZlPYFUdUpwnC8HQFYlMuYwZ7eOlzDXqY9Iej0y6OiQWs/LRV+npCnoWoCbVKXFzoxFXOTK7g1Ve4fL1MWtvt3GgdFgM5VTK9BAU2KDni6/tg0n1PqxV8iLlKlstl0maZzVJXVYTpxJqIK/MyGifTPVIyd0tcLGgYaWupbd5afrKgL9CjE6qLxh1ZejknPDW/6xUswJFMyCjXngHdZlLJ+OLmAqx+l6ArmIac65CBCXFqcnLXMavv1BGCMwlnxf0TfbCnlwoJ4BWYvbVg/z6T1n87zJu8NlQf8xKaOrzSuavNkxH+wCmuYrPL/EjSE4BtXo9g/+e5X6aP0owFQrgMoAK4uindKu02Ra/o1uW3ka3YVl26KvjJqLDvsluE+jFw58TfP4QfrlO/HR6uMQCJfwgCBdhmtyGeZgeLhb6dDxtFcwPf/7Dxxiqu6WIGT+GcS5DZ8LUPJJviAukFEP4rb1+shOojaN1Radvk49hCWCbDF+vDZosNXb0W3tE+nr9afgRhvg2ERdwFTAOk/HrgARNt7qxTWWqrYI3wR7TJBCXVLX8PPeDuYD11X1ysUUuC9dCKg1xPwTEqENvfHU0THas3rdG4ljNb4+BuSmmGRTQleXJcktg5EeIuaJuKrDYIvDlV779Ff47WP2vsOBBAH+NCw+C+A8Z8SCs+/CiOSwHcxqWg0mbsAey/xJX7dT7C1y1VfMeXGVWs1dT+ppbdBBXxclZLV0ppWauljUhz/QQ4bYvjuRl1ftdGki3BUp3PSuur9EP6OonaKcY1TysoQanC9AmG7bwIQeJVMTUmcTXL3yhawRoheYzLaQEiwhI/0qvyWyGyQNebbHy/6X6/Fv1Ga92dcMAPB1ub2CFgSd+I2V5NUd9jBYncKakWNTh8Um06Ia0PwRatNQoOCrM5Fm2lrxkd/q2zGR7UOGo+jfhr1oPmMz6TcN6AndYsu92u7caeVyKnhR4kHEFKkpKfBKdZ3GwWE3hDj1N/Y+YpkiSfbXEl2+W+LOQtiQlLEWhYkFw/8uocIXLtbJ8n8g5dXRLvOtQkofKuXvlNMLQ4oj0HdUEmFZKjC5cwSHxTHlugiVyg/HQEdrbZLpagBvkE5ZHeJyqf4L1cp6Gf6yiNIQhogW0pF5cWUECxuPVYrEhTz4nPxe+XKRwekgRjSatoWtpQ2ykhnvHdIt0Xybh6l2vZjN4HWUXW1uzSXEAUeEz/kFr4IdJXVra2pEzw8VtnN88TywWXnfxpIvh1KDLxstrPWWSXOLXAptfyFXNzK9+JSVRegWq5G32SJRdr3dz9mCLmQZG6RvlDLLAB6iY7lBxpxpRclOpjnvcbIopV5YQMxnqDZYC7svbeZiGtU9+VvPjWpimmLQEUovTYkOoZjx0AUItn4e1a/hBWZgOweo6mNykXrzPkpjfqclVNrz7OMQ8GnIxpOXxD9mQ1hiR3/Xkfd8yWNwX+0r1OlOXhNf9MKtv2Hu/upxMLLHfbWQwwN2mWJzgskURMXxj3EUfhyUh9VVIT6ipuFXgJea8VEPESKQctlwEDOyto/utzF+Q3ZUv/PCFEfLjoXV4vxV9FLWjj0frRh8pZEZu4I198YDWPimWy5AlX5B5aHPAse0LCiIFkSnSCRM4OBRZozHolq8ytoreReCCeP9A+QO3fHc7XfW+XrsXhFUVNXquJb+1RkXDUVNL+VV0qtjoIP2YlftR+325NEIut5RpMyKAsxFOX4l9EQo1N03yMcqlOcJUXAOpRiaTY4DxD4Og0YB6iTH3iwOh4SmvFS6e+rf+Atb/GjB+Cr+INagQUG8NAoNn7t8AkAirxvNQc//hXsteJRGhLLmOp1+pTG5UtrV8WvED7eIREycU3JcQuhx0agU5F2LFaTiJm+iwhFiZeChU9k6SYkhhFHR6Pai+Xu6VrbaUabEFjAEBJdYyh9ssfLQc8/fOV6jLBwtppqCs9766MzjT7gwuV2pb8uI4I6Y1jW+rCRHdQ6Dl+QsRtAPhV39R3q9UAwWBwwe3wW9HlEJUKIXoa0ohOqoUIqkUouNKIdpWCtG+UojuoRQiXSlElVKINKUQaUoh0pRCpCmFSCiFE0KKdEO0rRuiv6gbVDDWf6Ib4iO6IdrRDVGhG9QAxffWDRmQC3OpG+hiplVM2uHYIEmNYZp7DR8Y9EyueB8V9MykuLEtQY90Qc9KoY7uL9TQBfeX6yJKLqY4upzRuOKHlGFGz0rAFTserKCKMl/opajSSw5dyguj/OkyGx6gQnm9UrYfr7etHSodIAQ/a8mrJw0htok8u0Vp/YLGu7q4GVNO+GiSGNKp63B3nhgVN8O1RACdcXY19pt/2s3BxPruLDLva/rIsam4WwGvUSQkBSTLXZHUorvJkk39u7toUx/+m/Bj9XLrgm6I3N69EInrBN6WH9eHqE5lRgdWzvHph/oPVnX7pgBmIe/QJoYqffTGLLpFytZrF+vmX1kO26LDKlar5OG0Rr0jn7WIl7Lqm7oYbTVeRPvdOyuLCyuLEfn9rnX6++a7M/O+ykZgoV1ZRvkUFbPVDsCuCaq8/5COE+bGGTvTLpznd5tjN25JvOU/N1HhmZ0al0NjXP9hcmkaxEeTgplOzd8dE9+Hqkzz8vepZa7rhipg/X72/em/Wv/Df2+ibH1t5OkqXM98TERMUzDi/2vfaU54wumoyGUyTsfuZMLL6z0pFxMPc1gU8qpC9Fv20AjytbCQa9Kua1gsjMrlYV1JUMxhee2rTBYNdGgnqmiiTp0lNUf5VXTHht1o/zpNuTskg2PuNtq2oXaLdHEFUUIiH5HIR7sin0iRh/4s9z/k1hj9ku2j7bdvUFtNvzVLVks+Yh4VTadhTJxGG5YEqOhNuGGZv7WeVXIXYZqb+b5mgoIHewn0IqIXHVXllFUFkW9YegTqPs9Wuz1jAighirciR4NL6xhVGBsxUZFkeWEFig8qWQZO+SJMZt9s70QNaqH6sloVVGmIUEKMsXJnnLDN6HLbhBf/msFEfKYFPlrlQ2IWpVn+Blw5LHw1+SyOKKpUETB6eNLo0qTRHCe8Yi1R7TJt7cInyUgmZRzVsnBMEiZ9MJPdwQoOqZAWUEv1E/02/JtFck1OyPtgwfMNJiVqD3mWhuGfoaF9Nkf/F82+x9g="},
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
