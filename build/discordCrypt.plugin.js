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
 * @property {Buffer} signature The signed Ed25519 signature for the update payload.
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
 * @typedef {Object} PassphraseOptions
 * @desc Parameters for generating a passphrase using the Diceware list.
 * @property {number} [words] The number of words of the desired passphrase to generate.
 * @property {number} [security] The desired security level in bits.
 *      This overrides the [words] parameter if specified.
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
const discordCrypt = ( ( ) => {

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
     * @desc The branch name used for receiving updates.
     * @type {string}
     */
    const UPDATE_BRANCH = 'master';

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
     * @desc The Nothing-Up-My-Sleeve magic for KMAC key derivation for message payloads.
     *      This parameter ( P ) is used when combining the given master key, MK with a 64 bit salt S.
     *      It produces a unified key and IV such that:
     *          KEY = KMAC( MK, S, P )
     *      Where KEY corresponds to a concatenated message key ( mK ) and message IV ( mIV ).
     * @type {Buffer}
     */
    const ENCRYPT_PARAMETER = Buffer.from( 'DiscordCrypt KEY GENERATION PARAMETER' );

    /**
     * @private
     * @desc The Nothing-Up-My-Sleeve magic for KMAC authentication tags added to messages.
     *      This parameter is used when computing the 256-bit authentication tag of a message.
     *      The parameters used here are:
     *          Primary Key: PK
     *          Secondary Key: SK
     *          Ciphertext Message: M
     *          Magic Parameter: P
     *      This produces the authentication tag of the message ( T ) such that:
     *          T = KMAC( PK || SK, M, P )
     *      N.B. "||" denotes concatenation.
     * @type {Uint8Array}
     */
    const AUTH_TAG_PARAMETER = new Uint8Array( Buffer.from( 'discordCrypt MAC' ) );

    /**
     * @private
     * @desc The Nothing-Up-My-Sleeve magic for the KMAC-256 derivation for the primary key.
     *      This parameter is used when computing the primary key during a key exchange.
     *      The parameters used here are:
     *          Primary Salt: S
     *          Derived Secret: M
     *          Magic Parameter: P
     *      This derives the primary encryption key such that:
     *          PRIMARY_KEY = KMAC( S, M, P )
     * @type {Uint8Array}
     */
    const PRIMARY_KEY_PARAMETER = new Uint8Array( Buffer.from( 'discordCrypt-primary-secret' ) );

    /**
     * @private
     * @desc The Nothing-Up-My-Sleeve magic for the KMAC-256 derivation for the secondary key.
     *      This parameter is used when computing the secondary key during a key exchange.
     *      The parameters used here are:
     *          Secondary Salt: S
     *          Derived Secret: M
     *          Magic Parameter: P
     *      This derives the secondary encryption key such that:
     *          PRIMARY_KEY = KMAC( S, M, P )
     * @type {Uint8Array}
     */
    const SECONDARY_KEY_PARAMETER = new Uint8Array( Buffer.from( 'discordCrypt-secondary-secret' ) );

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
     * @desc Stores the base64 encoded Ed25519 public key used for update verification.
     * @type {string}
     */
    const ED25519_SIGNING_KEY = 'RGqTzo1dadMTGA7FTu8pIeIfZKTfIIM5BThvtvpTt0I=';

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
        'curve25519.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'scrypt.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sha3.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sidh.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sjcl.js': {"requiresNode":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresNode":false,"requiresBrowser":true,"minify":true,"code":"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"},
    };

    const BLACKLISTED_GUILDS = JSON.parse(
        _zlib.inflateSync(
            Buffer.from(
                `eNpl0EtKA0EQBuCrDL12Ua+urnKnxNdGBL3AmBQx+EjMjAERL+URPJk9ecAEdw399V9/9VfTJDIwUCnkZOimWdNpk86j72M9WXTT5Xr2+5NOqjQFkCLiqo4CYv/gjiGbFLOiuSDV88D2oDm7u9ki9AL1il2MGQFMx+ohuhrabSUBqKJx7WhQACWP5fXnKu7fP9rdaMFS6g4sxFizuYzpJDbxslwdclGdsjo7YX1S/wDG+GITb/2+gJrhEJfNfGh6VOAyYvbYTp8PXUUyMqGjUXY6yrxqX6O5Xcyf+vT9B30bYcE=`,
                'base64'
            ),
            { windowBits: 15 }
        ).toString( 'utf8' )
    );

    /**
     * @desc Compressed Diceware word list provided by the official Diceware website for passphrase generation.
     * @see https://world.std.com/~reinhold/diceware.html
     * @type {string[]}
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
            return '2.1.0';
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
                if ( code !== 13 || unlock_btn.attr( 'disabled' ) )
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
             * @param {string|Buffer} primary_key The primary key used for decryption.
             * @param {string|Buffer} secondary_key The secondary key used for decryption.
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
                .substr( 8 ), primary_key, secondary_key, metadata[ 0 ], metadata[ 1 ], metadata[ 2 ] );

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
            let cleaned, id = channel_id || '0';

            /* Skip messages starting with pre-defined escape characters. */
            if ( message.substr( 0, 2 ) === "##" )
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

            /* Get the properties for this channel & skip if we're in a blacklisted guild. */
            let props = _discordCrypt._getChannelProps( channel_id );
            if( props.type === 0 && BLACKLISTED_GUILDS.hasOwnProperty( props.guild_id ) ) {
                _discordCrypt.log( 'Blacklisted Guild. Ignoring outgoing message ...', 'warn' );
                return false;
            }

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
                    _configFile.paddingMode
                );

                /* Append the header to the message normally. */
                msg = ENCODED_MESSAGE_HEADER + _discordCrypt.__metaDataEncode
                (
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    parseInt( _crypto.pseudoRandomBytes( 1 )[ 0 ].toString() )
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
                    _configFile.paddingMode
                );

                /* Append the header to the message normally. */
                msg = ENCODED_MESSAGE_HEADER + _discordCrypt.__metaDataEncode
                (
                    _configFile.encryptMode,
                    _configFile.encryptBlockMode,
                    _configFile.paddingMode,
                    parseInt( _crypto.pseudoRandomBytes( 1 )[ 0 ].toString() )
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
         * @param {string} [channel_id] If specified, sends the message to this channel instead of the current channel.
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
                /* Skip on empty passwords. */
                if( !pwd_field.val().length )
                    return;

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
                let pwd = global.scrypt.hash
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
            // noinspection JSCheckFunctionSignatures
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
            /**
             * @desc Formats an input string or array into a hex string.
             * @param {string|Buffer|Uint8Array} input The input buffer.
             * @param {boolean} align Whether to break the line every 16 bytes.
             * @return {string}
             */
            const __binaryFormat = ( input, align ) => {
                let ret = '';

                if( !Buffer.isBuffer( input ) )
                    input = Buffer.from( input );

                input = Array.prototype.map.call( input, x => `00${x.toString( 16 ).toUpperCase()}`.slice( -2 ) );

                for( let i = 0; i < input.length; i++ )
                    ret += `${align && i && i % 16 === 0 ? "\n" : ''}${input[ i ]} `;

                return ret.trim();
            };

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
                    global.smalltalk.alert(
                        'Update Info',
                        `<strong>Version</strong>: ${updateInfo.version}\n\n` +
                        `<strong>Verified</strong>: ${updateInfo.valid ? 'Yes' : 'No'}\n\n` +
                        `<strong>Hash</strong>: ${updateInfo.hash.toUpperCase()}\n\n` +
                        `<strong>Signature</strong>:\n` +
                        '<code class="hljs dc-code-block" style="background: none !important;">' +
                        `\n${__binaryFormat( updateInfo.signature, true )}\n</code>`
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
            // noinspection JSCheckFunctionSignatures
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
            if ( !files || !files.length )
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
                        if ( !file || !file.length )
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
                let pwd = global.scrypt.hash
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
            /* Resolve all users, guilds and channels the current user is a part of. */
            // noinspection JSUnresolvedFunction
            let users = _cachedModules.UserStore.getUsers(),
                guilds = _cachedModules.GuildStore.getGuilds(),
                channels = _cachedModules.ChannelStore.getChannels();

            let channel_name = $( '#dc-password-channel-name' );

            /* Get the ID for the channel being viewed. */
            let id = _discordCrypt._getChannelId();

            do {
                /* Skip channels that don't have an ID. */
                if ( !channels[ id ] || [ 0, 1, 3 ].indexOf( channels[ id ].type ) === -1 ) {
                    channel_name.text( 'Unknown' );
                    break;
                }

                /* Check for the correct channel type. */
                if ( channels[ id ].type === 0 ) {
                    /* GUILD_TEXT */
                    let guild = guilds[ channels[ id ].guild_id ];

                    /* Resolve the name as a "Guild ( #Channel )" format. */
                    channel_name.text( `${guild.name} ( #${channels[ id ].name} )` );
                    break;
                }
                else if ( channels[ id ].type === 1 ) {
                    /* DM */
                    // noinspection JSUnresolvedVariable
                    let user = users[ channels[ id ].recipients[ 0 ] ];

                    /* Indicate this is a DM and give the full user name. */
                    channel_name.text( `@${user.username}` );
                    break;
                }

                /* GROUP_DM */

                /* Try getting the channel name first. */
                if ( channels[ id ].name )
                    channel_name.text( channels[ id ].name );
                else {
                    // noinspection JSUnresolvedVariable
                    let max = channels[ id ].recipients.length > 3 ? 3 : channels[ id ].recipients.length,
                        participants = '';

                    /* Iterate the maximum number of users we can display. */
                    for ( let i = 0; i < max; i++ ) {
                        // noinspection JSUnresolvedVariable
                        let user = users[ channels[ id ].recipients[ i ] ];
                        participants += `@${user.username}#${user.discriminator} `;
                    }

                    /* List a maximum of three members. */
                    channel_name.text( `${participants}` );
                }
            }
            // eslint-disable-next-line
            while( false );

            /* Show the password field. */
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
                'Be advised that a minimum security level of <b><u>192</u></b> bits is recommended.\n\n' +
                'Read about Security Levels ' +
                '<a href="https://en.wikipedia.org/wiki/Security_level" target="_blank">here</a>.\n\n',
                '192'
            ).then(
                ( value ) => {
                    /* Validate the value entered. */
                    // noinspection JSCheckFunctionSignatures
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
                        `GENERATED A PASSPHRASE WITH ${parseInt( value )} BITS OF SECURITY`,
                        `This passphrase contains <b>${
                            parseFloat( entropy.toString() ).toFixed( 3 )
                        } bits</b> of entropy and was generated using a word list containing <b>${
                            DICEWARE_WORD_LIST.length
                        }</b> words.\n\n\n` +
                        `How long would this take a supercomputer to crack ?\n\n` +
                        'Assume a supercomputer can guess 1 <i>nonillion</i> passwords per second. ' +
                        '( 1,000,000,000,000,000,000,000,000,000,000x or 10^30 ):\n\n' +
                        'It would take it about ' +
                        `${
                            _discordCrypt.__exponentialString( Math.pow( 2, entropy ) / 1e30 / 31536000 )
                        } <b>years</b> to crack.\n\n\n` +
                        'Here\'s your passphrase:\n\n',
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
                secondarySalt = Buffer.compare( primarySalt, _state.localKey.salt ) === 0 ?
                    _state.remoteKey.salt :
                    _state.localKey.salt;

            /* Calculate the KMACs for the primary and secondary key. */
            // noinspection JSUnresolvedFunction
            return {
                primaryKey: convert(
                    global.sha3.kmac256( primarySalt, derivedKey, outputBitLength, PRIMARY_KEY_PARAMETER )
                ),
                secondaryKey: convert(
                    global.sha3.kmac256( secondarySalt, derivedKey, outputBitLength, SECONDARY_KEY_PARAMETER )
                )
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
            let path = _path.join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() ),
                exists = _fs.existsSync( path );

            /* Do a debug log in case for some strange reason the file does exist but still can't be found by the FS. */
            if( !exists )
                _discordCrypt.log( `Could not find the plugin's file.\nExpected: "${path}" ...`, 'error' );
            return exists;
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
            const DEB_PATH = `${_process.env.HOME}/.config`;

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
            const repo_url = `https://gitlab.com/leogx9r/discordCrypt/raw/${UPDATE_BRANCH}`;
            const update_url = `${repo_url}/build/${_discordCrypt._getPluginName()}`;
            const changelog_url = `${repo_url}/CHANGELOG`;
            const signature_url = `${update_url}.sig.bin`;

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
                            _discordCrypt.__getRequest(
                                changelog_url,
                                ( statusCode, errorString, changelog ) => {
                                    updateInfo.changelog = statusCode === 200 ? changelog : '';

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
                        _discordCrypt.__getRequest(
                            signature_url,
                            ( statusCode, errorString, detached_sig ) => {
                                /* Skip on error. */
                                if( statusCode !== 200 ) {
                                    tryResolveChangelog( false );
                                    return;
                                }

                                /* Store the signature. */
                                updateInfo.signature = detached_sig;

                                /* Validate the signature then execute the callback. */
                                tryResolveChangelog(
                                    _discordCrypt.__validateEd25519Signature(
                                        updateInfo.payload,
                                        updateInfo.signature,
                                        Buffer.from( ED25519_SIGNING_KEY, 'base64' )
                                    )
                                );
                            },
                            null
                        );
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
         * @param {string} [channel_id] Sends the embedded message to this channel instead of the current channel.
         * @param {number} [timeout] Optional timeout to delete this message in minutes.
         */
        static _dispatchMessage( message, channel_id = null, timeout = null ) {
            if( !message.length )
                return;

            /* Save the Channel ID. */
            let _channel = channel_id || _discordCrypt._getChannelId();

            /* Get the properties for this channel & skip if we're in a blacklisted guild. */
            let props = _discordCrypt._getChannelProps( _channel );
            if( props.type === 0 && BLACKLISTED_GUILDS.hasOwnProperty( props.guild_id ) ) {
                _discordCrypt.log( 'Blacklisted Guild. Ignoring outgoing message ...', 'warn' );
                return;
            }

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
                        // noinspection JSCheckFunctionSignatures
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
         * @param {PatchCallback} [options.before] Callback that will be called before original target
         *      method call. You can modify arguments here, so it will be passed to original method.
         *      Can be combined with `after`.
         * @param {PatchCallback} [options.after] Callback that will be called after original
         *      target method call. You can modify return value here, so it will be passed to external code which calls
         *      target method. Can be combined with `before`.
         * @param {PatchCallback} [options.instead] Callback that will be called instead of original target method call.
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
            what[ methodName ].__monkeyPatched = true;
            what[ methodName ].displayName = `Hooked ${what[ methodName ].displayName || methodName}`;

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
         * @desc Converts an exponential represented number to the long string interpretation.
         * @param {Number} number The input number.
         * @returns {string}
         */
        static __exponentialString( number ) {
            let segments = number.toExponential().replace( '.' , '' ).split( /e/i ),
                suffix = '',
                num = segments[ 0 ],
                magnitude = Number( segments[ 1 ] );

            if( magnitude >= 0 && num.length > magnitude ) {
                magnitude += 1;
                return `${num.substring( 0, magnitude )}.${num.substring( magnitude )}`;
            }

            if( magnitude < 0 ) {
                while( ++magnitude )
                    suffix += '0';

                return `0.${suffix}${num}`;
            }

            magnitude = ( magnitude - num.length ) + 1;

            while( magnitude > suffix.length )
                suffix += '0';

            return num + suffix;
        }

        /**
         * @private
         * @desc Verifies an Ed25519 signature.
         * @param {string|Buffer|Uint8Array} payload The raw payload.
         * @param {Buffer|Uint8Array} signature The detached 512-bit signature.
         * @param {Buffer|Uint8Array} key The raw 256-bit public key.
         * @return {boolean} Returns true if the signature is valid for the given message.
         */
        static __validateEd25519Signature( payload, signature, key ) {
            /* Create a new curve object and set the public key. */
            let curve = new global.Curve25519();
            curve.setPublicKey( Buffer.from( key ) );

            try {
                /* Attempt to verify the signature. */
                return curve.verify( Buffer.from( payload ), Buffer.from( signature ) );
            }
            catch ( ex ) {
                /* Return false on any errors. */
                return false;
            }
        }

        /**
         * @private
         * @desc Builds a random captcha phrase to validate user input.
         * @param {PassphraseOptions} options The word length of entropy level desired.
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
            switch( Buffer.compare( a, b ) ) {
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
                        require( 'module' ).wrap( code ),
                        {
                            filename: name,
                            displayErrors: false
                        }
                    )( module.exports, require, module, name, __dirname, process, global, Buffer );
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

            /* Add the message header and return the encoded message. */
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
                // noinspection JSCheckFunctionSignatures
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
                // noinspection JSCheckFunctionSignatures
                output[ 'salt' ] = Buffer.from( msg.subarray( 2, 2 + salt_len ) );

                /* Read the key. */
                // noinspection JSCheckFunctionSignatures
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
            if ( clipboard.availableFormats().length === 0 )
                return { mime_type: '', name: '', data: null };

            /* Get all available formats. */
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
                if ( _file[ i ] !== file_header[ i ] ) {
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
         * @param {PassphraseOptions} options The word length of entropy level desired.
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
         * @param {string|int} primary_cipher The primary cipher.
         *      This can be either [ 'bf', 'aes', 'camel', 'idea', 'tdes' ] or an index which will be returned.
         * @param {string|int} [secondary_cipher] The secondary cipher.
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
         * @param {boolean} [is_base_64] Whether the public key is a Base64 string.
         *      If false or undefined, it is assumed to be hex.
         * @param {boolean} [to_base_64] Whether to convert the output secret to Base64.
         *      If false or undefined, it is converted to hex.
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

                /**
                 * Assume this is an SIDH key pair and call the method to generate the derived secret.
                 * @type {Buffer}
                 */
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
                if ( private_key === undefined )  {
                    // noinspection JSCheckFunctionSignatures
                    key.generateKeys( 'hex', 'compressed' );
                }
                else if ( typeof key.setPrivateKey !== 'undefined' )
                    key.setPrivateKey( private_key );
            }

            /* Return the result. */
            return key;
        }

        /**
         * @public
         * @desc Substitutes an input Buffer() object to the Braille equivalent from __getBraille().
         * @param {string|Buffer} message The input message to perform substitution on.
         * @param {boolean} [convert] Whether the message is to be converted from hex to Braille or from Braille to hex.
         * @returns {string} Returns the substituted string encoded message.
         * @throws An exception indicating the message contains characters not in the character set.
         */
        static __substituteMessage( message, convert = undefined ) {
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
         * @param {int|string} cipher_index The index of the cipher(s) used to encrypt the message
         * @param {int|string} cipher_mode_index The index of the cipher block mode used for the message.
         * @param {int|string} padding_scheme_index The index of the padding scheme for the message.
         * @param {int|string} pad_byte The padding byte to use.
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
         * @param {string} output_format The output format of the plaintext.
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
            // noinspection JSUnresolvedFunction
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
         * @param {Buffer|string} primary_key The primary key used for the first level of encryption.
         * @param {Buffer|string} secondary_key The secondary key used for the second level of encryption.
         * @param {int} cipher_index The cipher index containing the primary and secondary ciphers used for encryption.
         * @param {string} block_mode The block operation mode of the ciphers.
         *      These can be: [ 'CBC', 'CFB', 'OFB' ].
         * @param {string} padding_mode The padding scheme used to pad the message to the block length of the cipher.
         *      This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ].
         *      This prepends a 64 bit seed used to derive encryption keys from the initial key.
         * @returns {string|null|number} Returns the encrypted and substituted ciphertext of the message or on failure,
         *      a number indicating the error code or null on an unknown error
         * @throws An exception indicating the error that occurred.
         */
        static __symmetricEncrypt( message, primary_key, secondary_key, cipher_index, block_mode, padding_mode ) {
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
                AUTH_TAG_PARAMETER
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
         * @param {Buffer|string} primary_key The primary key used for the **second** level of decryption.
         * @param {Buffer|string} secondary_key The secondary key used for the **first** level of decryption.
         * @param {int} cipher_index The cipher index containing the primary and secondary ciphers used for decryption.
         * @param {string|int} block_mode The block operation mode of the ciphers.
         *      These can be: [ 'CBC', 'CFB', 'OFB' ] or an index representing them.
         * @param {string|int} padding_mode The padding scheme used to unpad the message to the block length of the
         *     cipher. This can be either [ 'ANS1', 'PKC7', 'ISO1', 'ISO9' ] or an index representing them. If this is
         *     enabled and authentication fails, null is returned. This prepends a 64 bit seed used to derive
         *     encryption keys from the initial key.
         * @returns {string|null|number} Returns the encrypted and substituted ciphertext of the message or on failure,
         *      a number indicating the error code or null on an unknown error.
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
                // noinspection JSCheckFunctionSignatures
                let tag = Buffer.from( message.subarray( 0, 32 ) );

                /* Strip off the authentication tag. */
                // noinspection JSCheckFunctionSignatures
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
         * @returns {string|null} Returns a hex or base64 string containing the resulting ciphertext or null on error.
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
