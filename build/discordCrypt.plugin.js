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
class discordCrypt {

    /* ============================================================== */

    /**
     * @typedef {Object} CachedModules
     * @desc Cached React and Discord modules for internal access.
     * @property {Object} MessageParser Internal message parser that's used to translate tags to Discord symbols.
     * @property {Object} MessageController Internal message controller used to receive, send and delete messages.
     * @property {Object} MessageActionTypes Internal message action types and constants for events.
     * @property {Object} MessageDispatcher Internal message dispatcher for pending queued messages.
     * @property {Object} MessageQueue Internal message Queue store for pending parsing.
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

    /* ============================================================== */

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
        return '1.2.1';
    }

    /* ============================================================== */

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
            `a#inbrowserbtn.btn{ display: none }.dc-overlay { position: fixed; font-family: monospace; display: none; width: 100%; height: 100%; left: 0; bottom: 0; right: 0; top: 0; z-index: 1000; cursor: default; transform: translateZ(0px); background: rgba(0, 0, 0, 0.85) !important;}.dc-password-field { width: 95%; margin: 10px; color: #ffffff; height: 10px; padding: 5px; background-color: #000000; border: 2px solid #3a71c1;}.dc-overlay-centerfield { position: absolute; top: 35%; left: 50%; font-size: 20px; color: #ffffff; padding: 16px; border-radius: 20px; background: rgba(0, 0, 0, 0.7); transform: translate(-50%, 50%);}.dc-overlay-main { overflow: hidden; position: absolute; left: 5%; right: 5%; top: 5%; bottom: 5%; width: 90%; height: 90%; border: 3px solid #3f3f3f; border-radius: 3px;}.dc-textarea { font-family: monospace; font-size: 12px; color: #ffffff; background: #000; overflow: auto; padding: 5px; resize: none; height: 100%; width: 100%; margin: 2px;}.dc-update-field { font-size: 14px; margin: 10px;}ul.dc-list { margin: 10px; padding: 5px; list-style-type: circle;}ul.dc-list > li { padding: 5px; }ul.dc-list-red { color: #ff0000; }.dc-overlay-main textarea { background: transparent !important; cursor: default; font-size: 12px; padding: 5px; margin-top: 10px; border-radius: 2px; resize: none; color: #8e8e8e; width: 70%; overflow-y: hidden; user-select: none;}.dc-overlay-main select { background-color: transparent; border-radius: 3px; font-size: 12px; color: #fff;}.dc-overlay-main select:hover { background-color: #000 !important; color: #fff;}.dc-input-field { font-family: monospace !important; background: #000 !important; color: #fff !important; font-size: 12px; width: 50%; margin-bottom: 10px; margin-top: -5px; margin-left: 10%;}.dc-input-label { font-family: monospace !important; color: #708090; min-width: 20%;}.dc-ruler-align { display: flex; margin: 10px;}.dc-code-block { font-family: monospace !important; font-size: 0.875rem; line-height: 1rem; overflow-x: visible; text-indent: 0; background: rgba(0,0,0,0.42)!important; color: hsla(0,0%,100%,0.7)!important; padding: 6px!important; position: relative;}.dc-overlay-main .tab { overflow: hidden; background-color: rgba(0, 0, 0, .9) !important; border-bottom: 3px solid #3f3f3f;}.dc-overlay-main .tab button { color: #008000; background-color: inherit; cursor: pointer; padding: 14px 14px; font-size: 14px; transition: 0.5s; font-family: monospace; border-radius: 3px; margin: 3px;}.dc-overlay-main .tab button:hover { background-color: #515c6b;}.dc-overlay-main .tab button.active { background-color: #1f1f2b;}.dc-overlay-main .tab-content { display: none; height: 95%; color: #9298a2; overflow: auto; padding: 10px 25px 5px; animation: fadeEffect 1s; background: rgba(0, 0, 0, 0.7) !important;}.dc-hint { font-size: 9px; display: block;}.dc-hint > p { margin: 0 0 0 30%;}.dc-svg { color: #fff; opacity: .6; margin: 0 4px; cursor: pointer; width: 24px; height: 24px;}.dc-svg:hover { color: #fff; opacity: .8;}.dc-button{ margin-right: 5px; margin-left: 5px; background-color: #7289da; color: #fff; align-items: center; border-radius: 3px; box-sizing: border-box; display: flex; font-size: 14px; width: auto; height: 32px; min-height: 32px; min-width: 60px; font-weight: 500; justify-content: center; line-height: 16px; padding: 2px 16px; position: relative; user-select: none;}.dc-button:hover{ background-color: #677bc4 !important; }.dc-button:active{ background-color: #5b6eae !important; }.dc-button-inverse{ color: #f04747; background: transparent !important; border: 1px solid rgba(240,71,71,.3); transition: color .17s ease,background-color .17s ease,border-color .17s ease;}.dc-button-inverse:hover{ border-color: rgba(240,71,71,.6); background: transparent !important;}.dc-button-inverse:active{ background-color: rgba(240,71,71,.1); }.stat-levels { box-shadow: inset 0 0 25px rgba(0,0,0,.5); margin: 5px auto 0 auto; height: 20px; padding: 15px; border: 1px solid #494a4e; border-radius: 10px; background: linear-gradient(#444549 0%, #343539 100%);}.stat-bar { background-color: #2a2b2f; box-shadow: inset 0 5px 15px rgba(0,0,0,.6); height: 8px; overflow: hidden; padding: 3px; border-radius: 3px; margin-bottom: 10px; margin-top: 10px; margin-left: 0;}.stat-bar-rating { border-radius: 4px; float: left; height: 100%; font-size: 12px; color: #ffffff; text-align: center; text-indent: -9999px; background-color: #3a71c1; box-shadow: inset 0 -1px 0 rgba(0, 0, 0, 0.15);}.stat-bar-rating { @include stat-bar(#cf3a02, #ff4500, top, bottom); }`;

        /**
         * @desc Contains the raw HTML used to inject into the search descriptor providing menu icons.
         * @type {string}
         */
        this.toolbarHtml =
            `<button type="button" id="dc-clipboard-upload-btn" style="background-color: transparent;"  title="Upload Encrypted Clipboard"> <svg x="0px" y="0px" width="30" height="30" viewBox="0 0 18 18" class="dc-svg">  <path fill="lightgrey"     d="M13 4h-3v-4h-10v14h6v2h10v-9l-3-3zM3 1h4v1h-4v-1zM15       15h-8v-10h5v3h3v7zM13 7v-2l2 2h-2z"/> </svg></button><button type="button" id="dc-file-btn" style="background-color: transparent;" title="Upload Encrypted File"> <svg class="dc-svg" width="24" height="24" viewBox="0 0 1792 1792" fill="lightgrey">  <path d="M768 384v-128h-128v128h128zm128 128v-128h-128v128h128zm-128      128v-128h-128v128h128zm128 128v-128h-128v128h128zm700-388q28 28 48       76t20 88v1152q0 40-28 68t-68 28h-1344q-40 0-68-28t-28-68v-1600q0-40 28-68t68-28h896q40       0 88 20t76 48zm-444-244v376h376q-10-29-22-41l-313-313q-12-12-41-22zm384 1528v-1024h-416q-40       0-68-28t-28-68v-416h-128v128h-128v-128h-512v1536h1280zm-627-721l107 349q8 27 8 52 0 83-72.5       137.5t-183.5 54.5-183.5-54.5-72.5-137.5q0-25 8-52 21-63 120-396v-128h128v128h79q22 0 39       13t23 34zm-141 465q53 0 90.5-19t37.5-45-37.5-45-90.5-19-90.5 19-37.5 45 37.5 45 90.5 19z">  </path> </svg></button><button type="button" id="dc-settings-btn" style="background-color: transparent;"  title="DiscordCrypt Settings"> <svg class="dc-svg" enable-background="new 0 0 32 32" version="1.1" viewBox="0 0 32 32"    width="20px" height="20px" xml:space="preserve">     <g>      <path fill="lightgrey" d="M28,10H18v2h10V10z M14,10H4v10h10V10z M32,0H0v28h15.518c1.614,2.411,      4.361,3.999,7.482,4c4.971-0.002,8.998-4.029,9-9         c0-0.362-0.027-0.718-0.069-1.069L32,22V0z M10,2h12v2H10V2z M6,2h2v2H6V2z M2,2h2v2H2V2z       M23,29.883         c-3.801-0.009-6.876-3.084-6.885-6.883c0.009-3.801,3.084-6.876,6.885-6.885c3.799,0.009,6.874,      3.084,6.883,6.885         C29.874,26.799,26.799,29.874,23,29.883z M29.999,      17.348c-0.57-0.706-1.243-1.324-1.999-1.83V14h-4.99c-0.003,0-0.007,0-0.01,0         s-0.007,0-0.01,0H18v1.516c-2.412,1.614-4,4.361-4,7.483c0,1.054,0.19,2.061,0.523,      3H2V6h27.999V17.348z M30,4h-4V2h4V4z"/>      <path fill="lightgrey" d="M28,      24v-2.001h-1.663c-0.063-0.212-0.145-0.413-0.245-0.606l1.187-1.187l-1.416-1.415l-1.165,1.166         c-0.22-0.123-0.452-0.221-0.697-0.294V18h-2v1.662c-0.229,0.068-0.446,0.158-0.652,      0.27l-1.141-1.14l-1.415,1.415l1.14,1.14         c-0.112,0.207-0.202,0.424-0.271,0.653H18v2h1.662c0.073,0.246,0.172,0.479,      0.295,0.698l-1.165,1.163l1.413,1.416l1.188-1.187         c0.192,0.101,0.394,0.182,0.605,0.245V28H24v-1.665c0.229-0.068,0.445-0.158,      0.651-0.27l1.212,1.212l1.414-1.416l-1.212-1.21         c0.111-0.206,0.201-0.423,0.27-0.651H28z M22.999,      24.499c-0.829-0.002-1.498-0.671-1.501-1.5c0.003-0.829,0.672-1.498,1.501-1.501         c0.829,0.003,1.498,0.672,1.5,1.501C24.497,23.828,23.828,24.497,22.999,24.499z"/>     </g>    </svg></button><button type="button" id="dc-lock-btn" style="background-color: transparent;"/><button type="button" id="dc-passwd-btn" style="background-color: transparent;" title="Password Settings"> <svg class="dc-svg" version="1.1" viewBox="0 0 32 32" width="20px" height="20px">  <g fill="none" fill-rule="evenodd" stroke="none" stroke-width="1">   <g fill="lightgrey">    <path d="M13.008518,22 L11.508518,23.5 L11.508518,23.5 L14.008518,26 L11.008518,       29 L8.50851798,26.5 L6.63305475,28.3754632 C5.79169774,29.2168202        4.42905085,29.2205817 3.5909158,28.3824466 L3.62607133,28.4176022 C2.78924,27.5807709        2.79106286,26.2174551 3.63305475,25.3754632 L15.7904495,13.2180685        C15.2908061,12.2545997 15.008518,11.1602658 15.008518,10 C15.008518,6.13400656 18.1425245,        3 22.008518,3 C25.8745114,3         29.008518,6.13400656 29.008518,10 C29.008518,13.8659934 25.8745114,17 22.008518,        17 C20.8482521,17 19.7539183,16.7177118 18.7904495,16.2180685         L18.7904495,16.2180685 L16.008518,19 L18.008518,21 L15.008518,24 L13.008518,22 L13.008518,        22 L13.008518,22 Z M22.008518,14 C24.2176571,14         26.008518,12.2091391 26.008518,10 C26.008518,7.79086089 24.2176571,6 22.008518,        6 C19.7993789,6 18.008518,7.79086089 18.008518,10 C18.008518,12.2091391         19.7993789,14 22.008518,14 L22.008518,14 Z" id="key"/>   </g>  </g> </svg></button><button type="button" id="dc-exchange-btn" style="background-color: transparent;" title="Key Exchange Menu"> <svg class="dc-svg" version="1.1" viewBox="0 0 78 78" width="20px" height="20px">  <path d="M72,4.5H6c-3.299,0-6,2.699-6,6V55.5c0,3.301,2.701,6,6,6h66c3.301,0,6-2.699,6-6V10.5     C78,7.2,75.301,4.5,72,4.5z M72,50.5H6V10.5h66V50.5z      M52.5,67.5h-27c-1.66,0-3,1.341-3,3v3h33v-3C55.5,68.84,54.16,67.5,52.5,67.5z        M26.991,36.5H36v-12h-9.009v-6.729L15.264,30.5l11.728,12.728V36.5z      M50.836,43.228L62.563,30.5L50.836,17.771V24.5h-9.009v12  h9.009V43.228z" style="fill:#d3d3d3;"/> </svg></button><button type="button" id="dc-quick-exchange-btn" style="background-color: transparent;"  title="Generate & Send New Public Key"> <svg class="dc-svg iconActive-AKd_jq icon-1R19_H iconMargin-2YXk4F" x="0px" y="0px" viewBox="0 0 58 58">  <path style="fill:#d3d3d3;"     d="M27.767,26.73c-2.428-2.291-3.766-5.392-3.766-8.729c0-6.617,5.383-12,12-12s12,5.383,12,12     c0,3.288-1.372,6.469-3.765,8.728l-1.373-1.455c2.023-1.909,     3.138-4.492,3.138-7.272c0-5.514-4.486-10-10-10s-10,4.486-10,10       c0,2.781,1.114,5.365,3.139,7.274L27.767,26.73z"/>  <path style="fill:#d3d3d3;" d="M56.428,38.815c-0.937-0.695-2.188-0.896-3.435-0.55l-15.29,4.227     C37.891,42.028,38,41.522,38,     40.991c0-2.2-1.794-3.991-3.999-3.991h-9.377c-0.667-1-2.363-4-4.623-4H16v-0.999       C16,30.347,14.654,29,13,29H9c-1.654,0-3,1.347-3,3v17C6,50.655,7.346,52,9,52h4c1.654,0,     3-1.345,3-2.999v-0.753l12.14,8.201       c1.524,1.031,3.297,1.55,5.075,1.55c1.641,0,3.286-0.441,4.742-1.33l18.172-11.101C57.283,     44.864,58,43.587,58,42.233v-0.312       C58,40.688,57.427,39.556,56.428,38.815z M14,49C14,49.553,13.552,     50,13,50h-1v-4h-2v4H9c-0.552,0-1-0.447-1-0.999v-17       C8,31.449,8.448,31,9,31h4c0.552,0,1,0.449,1,1V49z M56,42.233c0,0.66-0.35,1.284-0.913,     1.628L36.915,54.962       c-2.367,1.443-5.37,1.376-7.655-0.17L16,45.833V35h4c1.06,0,2.469,2.034,3.088,3.409L23.354,39h10.646       C35.104,39,36,39.892,36,40.988C36,42.098,35.104,43,34,43H29h-5v2h5h5h2l17.525-4.807c0.637-0.18,     1.278-0.094,1.71,0.228       C55.722,40.781,56,41.328,56,41.922V42.233z"/>  <path style="fill:#d3d3d3;" d="M33,25.394v6.607C33,33.655,     34.347,35,36,35H38h1h4v-2h-4v-2h2v-2h-2v-3.577       c3.02-1.186,5-4.079,5-7.422c0-2.398-1.063-4.649-2.915-6.177c-1.85-1.524-4.283-2.134-6.683-1.668       c-3.155,0.614-5.671,3.153-6.261,6.318C27.39,20.523,29.933,24.041,33,     25.394z M30.108,16.84c0.44-2.364,2.319-4.262,4.677-4.721       c1.802-0.356,3.639,0.104,5.028,1.249S42,     16.202,42,18c0,2.702-1.719,5.011-4.276,5.745L37,23.954V33h-0.999       C35.449,33,35,32.553,35,32v-8.02l-0.689-0.225C31.822,22.943,29.509,20.067,30.108,16.84z"/>  <path d="M36,22c2.206,0,4-1.794,4-4s-1.794-4-4-4s-4,1.794-4,4S33.795,22,36,22z     M36,16c1.103,0,2,0.897,2,2s-0.897,2-2,2s-2-0.897-2-2S34.898,16,36,16z"/>  <circle style="fill:#d3d3d3;" cx="36" cy="18" r="3"/> </svg></button>`;

        /**
         * @desc Contains the raw HTML injected into the overlay to prompt for the master password for database
         *      unlocking.
         * @type {string}
         */
        this.masterPasswordHtml =
            `<div id="dc-master-overlay" class="dc-overlay"> <div id="dc-overlay-centerfield" class="dc-overlay-centerfield" style="top: 30%">  <h2 style="color:#ff0000;" id="dc-header-master-msg"></h2>  <br/><br/>  <span id="dc-prompt-master-msg"></span><br/>  <input type="password" class="dc-password-field" id="dc-db-password" title="Database Password"/>  <br/>  <div class="stat stat-bar">   <span id = "dc-master-status" class="stat-bar-rating" style="width: 0;"/>  </div>  <div class="dc-ruler-align">   <button class="dc-button" style="width:100%;" id="dc-unlock-database-btn"/>  </div>  <div class="dc-ruler-align">   <button class="dc-button dc-button-inverse"     style="width:100%;" id="dc-cancel-btn">Cancel</button>  </div> </div></div>`;

        /**
         * @desc Defines the raw HTML used describing each option menu.
         * @type {string}
         */
        this.settingsMenuHtml =
            `<div id="dc-overlay" class="dc-overlay"> <div id="dc-overlay-upload" class="dc-overlay-centerfield" style="display:none; top: 5%;">  <div class="dc-ruler-align">   <input type="text" class="dc-input-field" id="dc-file-path"       style="width: 100%;padding: 2px;margin-left: 4px;" readonly title="File Path"/>   <button class="dc-button dc-button-inverse" type="button" id="dc-select-file-path-btn"     style="top: -8px;"> . . .</button>  </div>  <textarea class="dc-textarea" rows="20" cols="128" id="dc-file-message-textarea"      placeholder="Enter any addition text to send with your message ..." maxlength="1820"></textarea>  <div class="dc-ruler-align" style="font-size:14px; padding-bottom:10px;">   <input id="dc-file-deletion-checkbox" class="ui-switch-checkbox" type="checkbox"       title="Add Deletion Link">   <span style="margin-top: 5px;">Send Deletion Link</span>  </div>  <div class="dc-ruler-align" style="font-size:14px; padding-bottom:10px;">   <input id="dc-file-name-random-checkbox" class="ui-switch-checkbox" type="checkbox" checked       title="Use Random File Name">   <span style="margin-top: 5px;">Randomize File Name</span>  </div>  <div class="stat stat-bar">   <span id = "dc-file-upload-status" class="stat-bar-rating" style="width: 0;"/>  </div>  <div class="dc-ruler-align">   <button class="dc-button" style="width:100%;" id="dc-file-upload-btn">Upload</button>  </div>  <div class="dc-ruler-align">   <button class="dc-button dc-button-inverse" style="width:100%;" id="dc-file-cancel-btn">    Close</button>  </div> </div> <div id="dc-overlay-password" class="dc-overlay-centerfield" style="display:none;">  <span>Primary Password:</span>  <input type="password" class="dc-password-field" id="dc-password-primary" placeholder="..."/><br/>  <span>Secondary Password:</span>  <input type="password" class="dc-password-field" id="dc-password-secondary" placeholder="..."/><br/>  <div class="dc-ruler-align">   <button class="dc-button" id="dc-save-pwd">Update Passwords</button>   <button class="dc-button dc-button-inverse" id="dc-reset-pwd">Reset Passwords</button>   <button class="dc-button dc-button-inverse" id="dc-cancel-btn">Cancel</button>  </div>  <button class="dc-button dc-button-inverse" style="width: 100%;" id="dc-cpy-pwds-btn">   Copy Current Passwords</button> </div> <div id="dc-update-overlay" class="dc-overlay-centerfield"   style="top: 5%;border: 1px solid;display: none">  <span>DiscordCrypt: Update Available</span>  <div class="dc-ruler-align">   <strong class="dc-update-field" id="dc-new-version"/>  </div>  <div class="dc-ruler-align">   <strong class="dc-update-field" id="dc-old-version"/>  </div>  <div class="dc-ruler-align">   <strong class="dc-update-field">Changelog:</strong></div>  <div class="dc-ruler-align">   <textarea class="dc-textarea" rows="20" cols="128" id="dc-changelog" readonly title="Update Changes"/>  </div>  <br>  <div class="dc-ruler-align">   <button class="dc-button" id="dc-restart-now-btn" style="width: 50%;">    Restart Discord Now</button>   <button class="dc-button dc-button-inverse" id="dc-restart-later-btn" style="width: 50%;">    Restart Discord Later</button>  </div> </div> <div id="dc-overlay-settings" class="dc-overlay-main" style="display: none;">  <div class="tab" id="dc-settings-tab">   <button class='dc-tab-link' id="dc-exit-settings-btn" style="float:right;">[ X ]</button>  </div>  <div class="tab-content" id="dc-settings" style="display: block;">   <p style="text-align: center;">    <b>DiscordCrypt Settings</b>   </p>   <br/><br/>   <div class="dc-ruler-align">    <div class="dc-input-label">Primary Cipher:</div>    <select class="dc-input-field" id="dc-primary-cipher" title="Primary Cipher">     <option value="bf" selected>Blowfish ( 512-Bit )</option>     <option value="aes">AES ( 256-Bit )</option>     <option value="camel">Camellia ( 256-Bit )</option>     <option value="tdes">TripleDES ( 192-Bit )</option>     <option value="idea">IDEA ( 128-Bit )</option>    </select>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Secondary Cipher:</div>    <select class="dc-input-field" id="dc-secondary-cipher" title="Secondary Cipher">     <option value="bf">Blowfish ( 512-Bit )</option>     <option value="aes">AES ( 256-Bit )</option>     <option value="camel">Camellia ( 256-Bit )</option>     <option value="idea">IDEA ( 256-Bit )</option>     <option value="tdes">TripleDES ( 192-Bit )</option>    </select>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Cipher Padding Mode:</div>    <select class="dc-input-field" id="dc-settings-padding-mode" title="Cipher Padding Scheme">     <option value="pkc7">PKCS #7</option>     <option value="ans2">ANSI X9.23</option>     <option value="iso1">ISO 10126</option>     <option value="iso9">ISO 97971</option>    </select>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Cipher Block Operation Mode:</div>    <select class="dc-input-field" id="dc-settings-cipher-mode" title="Cipher Block Operation Mode">     <option value="cbc">Cipher Block Chaining</option>     <option value="cfb">Cipher Feedback Mode</option>     <option value="ofb">Output Feedback Mode</option>    </select>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Default Encryption Password:</div>    <input type="text" class="dc-input-field" id="dc-settings-default-pwd"        title="Default Encryption Password"/>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Scanning Frequency:</div>    <input type="text" class="dc-input-field" id="dc-settings-scan-delay"        title="Scanning Frequency"/>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Message Trigger:</div>    <input type="text" class="dc-input-field" id="dc-settings-encrypt-trigger" title="Message Trigger"/>   </div>   <div class="dc-hint">    <p>The suffix at the end of a typed message to indicate whether to encrypt the text.</p>    <p>Example: <u>This message will be encrypted.|ENC</u></p>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Timed Message Expiration:</div>    <input type="number" class="dc-input-field" id="dc-settings-timed-expire"        title="Timed Message Expiration"/>   </div>   <div class="dc-hint">    <p>This indicates how long after an encrypted message is sent, should it be deleted in minutes.</p>    <p><u>Set this to "0" to disable timed messages.</u></p>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">New Master Database Password:</div>    <input type="text" class="dc-input-field" id="dc-master-password"        title="New Master Database Password"/>   </div>   <div class="dc-ruler-align">    <div class="dc-input-label">Use Embedded Messages:</div>    <input type="checkbox" class="dc-input-field" id="dc-embed-enabled"        title="Use Embedded Messages"/>   </div>   <div class="dc-hint">    <p>If enabled, send all encrypted messages using embeds.</p>    <p>     <b style="color: #f00">WARNING:</b>     <b> Using this option may result in your embedded permissions being globally revoked.</b>    </p>   </div>   <div class="dc-ruler-align">    <button id="dc-settings-save-btn" class="dc-button">Save & Apply</button>    <button id="dc-settings-reset-btn" class="dc-button dc-button-inverse">     Reset Settings</button>   </div>   <br/><br/><br/><br/>  </div> </div> <div id="dc-overlay-exchange" class="dc-overlay-main" style="display: none;">  <div class="tab" id="dc-exchange-tab">   <button class='dc-tab-link' id="dc-tab-info-btn">Info</button>   <button class='dc-tab-link' id="dc-tab-keygen-btn">Key Generation</button>   <button class='dc-tab-link' id="dc-tab-handshake-btn">Secret Computation</button>   <button class='dc-tab-link' id="dc-exit-exchange-btn" style="float:right;">[ X ]</button>  </div>  <div class="tab-content" id="dc-about-tab" style="display: block;">   <p style="text-align: center;">    <b>Key Exchanger</b>   </p>   <br/>   <strong>What is this used for?</strong>   <ul class="dc-list">    <li>Simplifying the process or generating strong passwords for each user of DiscordCrypt     requires a secure channel to exchange these keys.</li>    <li>Using this generator, you may create new keys using standard algorithms such as     DH or ECDH for manual handshaking.</li>    <li>Follow the steps below and you can generate a password between channels or users     while being able to publicly post the messages.</li>    <li>This generator uses secure hash algorithms ( SHA-256 and SHA-512 ) in tandem with     the Scrypt KDF function to derive two keys.</li>   </ul>   <br/>   <strong>How do I use this?</strong>   <ul class="dc-list">    <li>Generate a key pair using the specified algorithm and key size on the     "Key Generation" tab.</li>    <li>Give your partner your public key by clicking the "Send Public Key" button.</li>    <li>Ask your partner to give you their public key using the same step above.</li>    <li>Copy your partner's public key and paste it in the "Secret Computation" tab and     select "Compute Secret Keys".</li>    <li>Wait for <span style="text-decoration: underline;color: #ff0000;">BOTH</span>     the primary and secondary keys to be generated.</li>    <li>A status bar is provided to easily tell you when both passwords     have been generated.</li>    <li>Click the "Apply Generated Passwords" button to apply both passwords to     the current user or channel.</li>   </ul>   <strong>Algorithms Supported:</strong>   <ul class="dc-list">    <li>     <a title="Diffie–Hellman key exchange"        href="https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange"        target="_blank" rel="noopener">Diffie-Hellman ( DH )</a>    </li>    <li>     <a title="Elliptic curve Diffie–Hellman"        href="https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman"        target="_blank" rel="noopener">Elliptic Curve Diffie-Hellman ( ECDH )</a>    </li>   </ul>   <span style="text-decoration: underline; color: #ff0000;">       <strong>DO NOT:</strong>      </span>   <ul class="dc-list dc-list-red">    <li>     <strong>Post your private key. If you do, generate a new one IMMEDIATELY.</strong>    </li>    <li>     <strong>Alter your public key or have your partner alter theirs in any way.</strong>    </li>    <li>     <strong>Insert a random public key.</strong>    </li>   </ul>   <br/><br/><br/><br/>  </div>  <div class="tab-content" id="dc-keygen-tab" style="display: block;">   <p style="text-align: center;">    <b style="font-size: large;">Secure Key Generation</b>   </p>   <br/>   <strong>Exchange Algorithm:</strong>   <select id="dc-keygen-method" title="Exchange Algorithm">    <option value="dh" selected>Diffie-Hellman</option>    <option value="ecdh">Elliptic-Curve Diffie-Hellman</option>   </select>   <br/><br/>   <strong>Key Length ( Bits ):</strong>   <select id="dc-keygen-algorithm" title="Key Length">    <option value="768">768</option>    <option value="1024">1024</option>    <option value="1536">1536</option>    <option value="2048">2048</option>    <option value="3072">3072</option>    <option value="4096">4096</option>    <option value="6144">6144</option>    <option value="8192" selected>8192</option>   </select>   <br/><br/>   <div class="dc-ruler-align">    <button id="dc-keygen-gen-btn" class="dc-button">Generate</button>    <button id="dc-keygen-clear-btn" class="dc-button dc-button-inverse">Clear</button>   </div>   <br/><br/><br/>   <strong>Private Key: (    <span style="text-decoration: underline; color: #ff0000;">KEEP SECRET</span>    )</strong><br/>   <textarea id="dc-priv-key-ta" rows="8" cols="128" maxsize="8192"       unselectable="on" disabled readonly title="Private Key"/>   <br/><br/>   <strong>Public Key:</strong><br/>   <textarea id="dc-pub-key-ta" rows="8" cols="128" maxsize="8192"       unselectable="on" disabled readonly title="Public Key"/>   <br/><br/>   <div class="dc-ruler-align">    <button id="dc-keygen-send-pub-btn" class="dc-button">Send Public Key</button>   </div>   <br/>   <ul class="dc-list dc-list-red">    <li>Never rely on copying these keys. Use the "Send Public Key" button     to send your key.</li>    <li>Public keys are automatically encoded with a random salts.</li>    <li>Posting these keys directly won't work since they aren't encoded     in the format required.</li>   </ul>   <br/><br/><br/><br/>  </div>  <div class="tab-content" id="dc-handshake-tab">   <p style="text-align: center;">    <b style="font-size: large;">Key Derivation</b>   </p>   <br/>   <p>    <span style="text-decoration: underline; color: #ff0000;">     <strong>NOTE:</strong>    </span>   </p>   <ul class="dc-list dc-list-red">    <li>Copy your partner's private key EXACTLY as it was posted.</li>    <li>Your last generated private key from the "Key Generation" tab     will be used to compute these keys.</li>   </ul>   <br/>   <strong>Partner's Public Key:</strong><br/>   <textarea id="dc-handshake-ppk" rows="8" cols="128" maxsize="16384" title="Partner's Public Key"/>   <br/><br/>   <div class="dc-ruler-align">    <button id="dc-handshake-paste-btn" class="dc-button dc-button-inverse">     Paste From Clipboard</button>    <button id="dc-handshake-compute-btn" class="dc-button">Compute Secret Keys</button>   </div>   <ul class="dc-list dc-list-red">    <li id="dc-handshake-algorithm">...</li>    <li id="dc-handshake-salts">...</li>    <li id="dc-handshake-secret">...</li>   </ul>   <br/>   <strong id="dc-handshake-prim-lbl">Primary Secret:</strong><br/>   <textarea id="dc-handshake-primary-key" rows="1" columns="128" maxsize="32768"       style="max-height: 14px;user-select: none;" unselectable="on" disabled       title="Primary Secret"/>   <br/><br/>   <strong id="dc-handshake-sec-lbl">Secondary Secret:</strong><br/>   <textarea id="dc-handshake-secondary-key" rows="1" columns="128" maxsize="32768"       style="max-height: 14px;user-select: none;" unselectable="on" disabled       title="Secondary Secret"/>   <br/><br/>   <div class="stat stat-bar" style="width:70%;">    <span id="dc-exchange-status" class="stat-bar-rating" style="width: 0;"/>   </div><br/>   <div class="dc-ruler-align">    <button id="dc-handshake-cpy-keys-btn" class="dc-button dc-button-inverse">     Copy Keys & Nuke</button>    <button id="dc-handshake-apply-keys-btn" class="dc-button">     Apply Generated Passwords</button>   </div>   <br/><br/><br/><br/>  </div> </div></div>`;

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
                        'currify.js': {"requiresElectron":false,"requiresBrowser":true,"code":"!function(n){if(\"object\"==typeof exports&&\"undefined\"!=typeof module)module.exports=n();else if(\"function\"==typeof define&&define.amd)define([],n);else{var r;(r=\"undefined\"!=typeof window?window:\"undefined\"!=typeof global?global:\"undefined\"!=typeof self?self:this).currify=n()}}(function(){var n,r,e;return function n(r,e,t){function o(f,u){if(!e[f]){if(!r[f]){var c=\"function\"==typeof require&&require;if(!u&&c)return c(f,!0);if(i)return i(f,!0);var p=new Error(\"Cannot find module '\"+f+\"'\");throw p.code=\"MODULE_NOT_FOUND\",p}var l=e[f]={exports:{}};r[f][0].call(l.exports,function(n){var e=r[f][1][n];return o(e||n)},l,l.exports,n,r,e,t)}return e[f].exports}for(var i=\"function\"==typeof require&&require,f=0;f<t.length;f++)o(t[f]);return o}({currify:[function(n,r,e){\"use strict\";var t=function n(r){return[function(n){return r.apply(void 0,arguments)},function(n,e){return r.apply(void 0,arguments)},function(n,e,t){return r.apply(void 0,arguments)},function(n,e,t,o){return r.apply(void 0,arguments)},function(n,e,t,o,i){return r.apply(void 0,arguments)}]};function o(n){if(\"function\"!=typeof n)throw Error(\"fn should be function!\")}r.exports=function n(r){for(var e=arguments.length,i=Array(e>1?e-1:0),f=1;f<e;f++)i[f-1]=arguments[f];if(o(r),i.length>=r.length)return r.apply(void 0,i);var u=function e(){return n.apply(void 0,[r].concat(i,Array.prototype.slice.call(arguments)))},c=r.length-i.length-1,p;return t(u)[c]||u}},{}]},{},[\"currify\"])(\"currify\")});\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIjAiXSwibmFtZXMiOlsiZiIsImV4cG9ydHMiLCJtb2R1bGUiLCJkZWZpbmUiLCJhbWQiLCJnIiwid2luZG93IiwiZ2xvYmFsIiwic2VsZiIsInRoaXMiLCJjdXJyaWZ5IiwiZSIsInQiLCJuIiwiciIsInMiLCJvIiwidSIsImEiLCJyZXF1aXJlIiwiaSIsIkVycm9yIiwiY29kZSIsImwiLCJjYWxsIiwibGVuZ3RoIiwiZm4iLCJhcHBseSIsInVuZGVmaW5lZCIsImFyZ3VtZW50cyIsImIiLCJjIiwiZCIsImNoZWNrIiwiX2xlbiIsImFyZ3MiLCJBcnJheSIsIl9rZXkiLCJhZ2FpbiIsImNvbmNhdCIsInByb3RvdHlwZSIsInNsaWNlIiwiY291bnQiLCJmdW5jIl0sIm1hcHBpbmdzIjoiQ0F3QkEsU0FBVUEsR0FDTixHQUF1QixpQkFBWkMsU0FBMEMsb0JBQVhDLE9BQ3RDQSxPQUFPRCxRQUFVRCxTQUNkLEdBQXNCLG1CQUFYRyxRQUF5QkEsT0FBT0MsSUFDOUNELFVBQVdILE9BQ1IsQ0FDSCxJQUFJSyxHQUVBQSxFQURrQixvQkFBWEMsT0FDSEEsT0FDcUIsb0JBQVhDLE9BQ1ZBLE9BQ21CLG9CQUFUQyxLQUNWQSxLQUVBQyxNQUVOQyxRQUFVVixLQWhCcEIsQ0FrQkcsV0FDQyxJQUFJRyxFQUFRRCxFQUFRRCxFQUNwQixPQUFPLFNBQVVVLEVBQUVDLEVBQUdDLEVBQUdDLEdBQ3JCLFNBQVNDLEVBQUVDLEVBQUdDLEdBQ1YsSUFBS0osRUFBRUcsR0FBSSxDQUNQLElBQUtKLEVBQUVJLEdBQUksQ0FDUCxJQUFJRSxFQUFzQixtQkFBWEMsU0FBeUJBLFFBQ3hDLElBQUtGLEdBQUtDLEVBQUcsT0FBT0EsRUFBRUYsR0FBRyxHQUN6QixHQUFJSSxFQUFHLE9BQU9BLEVBQUVKLEdBQUcsR0FDbkIsSUFBSWhCLEVBQUksSUFBSXFCLE1BQU0sdUJBQXlCTCxFQUFJLEtBQy9DLE1BQU1oQixFQUFFc0IsS0FBTyxtQkFBb0J0QixFQUV2QyxJQUFJdUIsRUFBSVYsRUFBRUcsSUFDTmYsWUFFSlcsRUFBRUksR0FBRyxHQUFHUSxLQUFLRCxFQUFFdEIsUUFBUyxTQUFTVSxHQUM3QixJQUFJRSxFQUFJRCxFQUFFSSxHQUFHLEdBQUdMLEdBQ2hCLE9BQU9JLEVBQUVGLEdBQVFGLElBQ2xCWSxFQUFHQSxFQUFFdEIsUUFBU1UsRUFBR0MsRUFBR0MsRUFBR0MsR0FFOUIsT0FBT0QsRUFBRUcsR0FBR2YsUUFHaEIsSUFEQSxJQUFJbUIsRUFBc0IsbUJBQVhELFNBQXlCQSxRQUMvQkgsRUFBSSxFQUFHQSxFQUFJRixFQUFFVyxPQUFRVCxJQUFLRCxFQUFFRCxFQUFFRSxJQUN2QyxPQUFPRCxFQXRCSixFQXdCSEwsU0FBWSxTQUFTUyxFQUFTakIsRUFBUUQsR0FDbEMsYUFFQSxJQUFJRCxFQUFJLFNBQVNBLEVBQUUwQixHQUNmLE9BRUksU0FBU1IsR0FDTCxPQUFPUSxFQUFHQyxXQUFNQyxFQUFXQyxZQUUvQixTQUFTWCxFQUFHWSxHQUNSLE9BQU9KLEVBQUdDLFdBQU1DLEVBQVdDLFlBRS9CLFNBQVNYLEVBQUdZLEVBQUdDLEdBQ1gsT0FBT0wsRUFBR0MsV0FBTUMsRUFBV0MsWUFFL0IsU0FBU1gsRUFBR1ksRUFBR0MsRUFBR0MsR0FDZCxPQUFPTixFQUFHQyxXQUFNQyxFQUFXQyxZQUUvQixTQUFTWCxFQUFHWSxFQUFHQyxFQUFHQyxFQUFHckIsR0FDakIsT0FBT2UsRUFBR0MsV0FBTUMsRUFBV0MsY0F3QnZDLFNBQVNJLEVBQU1QLEdBQ1gsR0FBa0IsbUJBQVBBLEVBQW1CLE1BQU1MLE1BQU0sMEJBcEI5Q25CLEVBQU9ELFFBQVUsU0FBU1MsRUFBUWdCLEdBQzlCLElBQUssSUFBSVEsRUFBT0wsVUFBVUosT0FBUVUsRUFBT0MsTUFBTUYsRUFBTyxFQUFJQSxFQUFPLEVBQUksR0FBSUcsRUFBTyxFQUFHQSxFQUFPSCxFQUFNRyxJQUM1RkYsRUFBS0UsRUFBTyxHQUFLUixVQUFVUSxHQUsvQixHQUZBSixFQUFNUCxHQUVGUyxFQUFLVixRQUFVQyxFQUFHRCxPQUFRLE9BQU9DLEVBQUdDLFdBQU1DLEVBQVdPLEdBRXpELElBQUlHLEVBQVEsU0FBU0EsSUFDakIsT0FBTzVCLEVBQVFpQixXQUFNQyxHQUFZRixHQUFJYSxPQUFPSixFQUFNQyxNQUFNSSxVQUFVQyxNQUFNakIsS0FBS0ssY0FHN0VhLEVBQVFoQixFQUFHRCxPQUFTVSxFQUFLVixPQUFTLEVBQ2xDa0IsRUFFSixPQUZXM0MsRUFBRXNDLEdBQU9JLElBRUxKLGFBT25CLFdBdkVELENBdUVhIn0="},
            'curve25519.js': {"requiresElectron":true,"requiresBrowser":false,"code":"\"use strict\";class curve25519{static init_25519_constants(r){const t=new Float64Array(16);if(r)for(let c=0;c<r.length;c++)t[c]=r[c];return t}static gf0(){return curve25519.init_25519_constants()}static gf1(){return curve25519.init_25519_constants([1])}static _121665(){return curve25519.init_25519_constants([56129,1])}static D(){return curve25519.init_25519_constants([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995])}static D2(){return curve25519.init_25519_constants([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222])}static X(){return curve25519.init_25519_constants([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553])}static Y(){return curve25519.init_25519_constants([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214])}static I(){return curve25519.init_25519_constants([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139])}static checkArrayTypes(){let r;for(let t=0;t<arguments.length;t++)if(\"[object Uint8Array]\"!==(r=Object.prototype.toString.call(arguments[t])))throw new TypeError(`unexpected type ${r}, use Uint8Array`)}static crypto_verify_32(r,t,c,n){function e(r,t,c,n,e){let o,u=0;for(o=0;o<e;o++)u|=r[t+o]^c[n+o];return(1&u-1>>>8)-1}return e(r,t,c,n,32)}static set25519(r,t){let c;for(c=0;c<16;c++)r[c]=0|t[c]}static sel25519(r,t,c){let n;const e=~(c-1);for(let c=0;c<16;c++)n=e&(r[c]^t[c]),r[c]^=n,t[c]^=n}static pack25519(r,t){function c(r){let t,c,n=1;for(t=0;t<16;t++)c=r[t]+n+65535,n=Math.floor(c/65536),r[t]=c-65536*n;r[0]+=n-1+37*(n-1)}let n,e,o;const u=curve25519.init_25519_constants(),s=curve25519.init_25519_constants();for(n=0;n<16;n++)s[n]=t[n];for(c(s),c(s),c(s),e=0;e<2;e++){for(u[0]=s[0]-65517,n=1;n<15;n++)u[n]=s[n]-65535-(u[n-1]>>16&1),u[n-1]&=65535;u[15]=s[15]-32767-(u[14]>>16&1),o=u[15]>>16&1,u[14]&=65535,curve25519.sel25519(s,u,1-o)}for(n=0;n<16;n++)r[2*n]=255&s[n],r[2*n+1]=s[n]>>8}static par25519(r){const t=new Uint8Array(32);return curve25519.pack25519(t,r),1&t[0]}static unpack25519(r,t){let c;for(c=0;c<16;c++)r[c]=t[2*c]+(t[2*c+1]<<8);r[15]&=32767}static blockadd(r,t,c){for(let n=0;n<16;n++)r[n]=t[n]+c[n]}static blocksub(r,t,c){for(let n=0;n<16;n++)r[n]=t[n]-c[n]}static blockround(r,t,c){let n,e,o=0,u=0,s=0,a=0,i=0,v=0,l=0,_=0,f=0,d=0,b=0,h=0,k=0,y=0,g=0,w=0,p=0,A=0,M=0,U=0,m=0,E=0,T=0,F=0,I=0,D=0,K=0,L=0,P=0,X=0,Y=0;const j=c[0],x=c[1],O=c[2],S=c[3],$=c[4],q=c[5],z=c[6],B=c[7],C=c[8],G=c[9],H=c[10],J=c[11],N=c[12],Q=c[13],R=c[14],V=c[15];o+=(n=t[0])*j,u+=n*x,s+=n*O,a+=n*S,i+=n*$,v+=n*q,l+=n*z,_+=n*B,f+=n*C,d+=n*G,b+=n*H,h+=n*J,k+=n*N,y+=n*Q,g+=n*R,w+=n*V,u+=(n=t[1])*j,s+=n*x,a+=n*O,i+=n*S,v+=n*$,l+=n*q,_+=n*z,f+=n*B,d+=n*C,b+=n*G,h+=n*H,k+=n*J,y+=n*N,g+=n*Q,w+=n*R,p+=n*V,s+=(n=t[2])*j,a+=n*x,i+=n*O,v+=n*S,l+=n*$,_+=n*q,f+=n*z,d+=n*B,b+=n*C,h+=n*G,k+=n*H,y+=n*J,g+=n*N,w+=n*Q,p+=n*R,A+=n*V,a+=(n=t[3])*j,i+=n*x,v+=n*O,l+=n*S,_+=n*$,f+=n*q,d+=n*z,b+=n*B,h+=n*C,k+=n*G,y+=n*H,g+=n*J,w+=n*N,p+=n*Q,A+=n*R,M+=n*V,i+=(n=t[4])*j,v+=n*x,l+=n*O,_+=n*S,f+=n*$,d+=n*q,b+=n*z,h+=n*B,k+=n*C,y+=n*G,g+=n*H,w+=n*J,p+=n*N,A+=n*Q,M+=n*R,U+=n*V,v+=(n=t[5])*j,l+=n*x,_+=n*O,f+=n*S,d+=n*$,b+=n*q,h+=n*z,k+=n*B,y+=n*C,g+=n*G,w+=n*H,p+=n*J,A+=n*N,M+=n*Q,U+=n*R,m+=n*V,l+=(n=t[6])*j,_+=n*x,f+=n*O,d+=n*S,b+=n*$,h+=n*q,k+=n*z,y+=n*B,g+=n*C,w+=n*G,p+=n*H,A+=n*J,M+=n*N,U+=n*Q,m+=n*R,E+=n*V,_+=(n=t[7])*j,f+=n*x,d+=n*O,b+=n*S,h+=n*$,k+=n*q,y+=n*z,g+=n*B,w+=n*C,p+=n*G,A+=n*H,M+=n*J,U+=n*N,m+=n*Q,E+=n*R,T+=n*V,f+=(n=t[8])*j,d+=n*x,b+=n*O,h+=n*S,k+=n*$,y+=n*q,g+=n*z,w+=n*B,p+=n*C,A+=n*G,M+=n*H,U+=n*J,m+=n*N,E+=n*Q,T+=n*R,F+=n*V,d+=(n=t[9])*j,b+=n*x,h+=n*O,k+=n*S,y+=n*$,g+=n*q,w+=n*z,p+=n*B,A+=n*C,M+=n*G,U+=n*H,m+=n*J,E+=n*N,T+=n*Q,F+=n*R,I+=n*V,b+=(n=t[10])*j,h+=n*x,k+=n*O,y+=n*S,g+=n*$,w+=n*q,p+=n*z,A+=n*B,M+=n*C,U+=n*G,m+=n*H,E+=n*J,T+=n*N,F+=n*Q,I+=n*R,D+=n*V,h+=(n=t[11])*j,k+=n*x,y+=n*O,g+=n*S,w+=n*$,p+=n*q,A+=n*z,M+=n*B,U+=n*C,m+=n*G,E+=n*H,T+=n*J,F+=n*N,I+=n*Q,D+=n*R,K+=n*V,k+=(n=t[12])*j,y+=n*x,g+=n*O,w+=n*S,p+=n*$,A+=n*q,M+=n*z,U+=n*B,m+=n*C,E+=n*G,T+=n*H,F+=n*J,I+=n*N,D+=n*Q,K+=n*R,L+=n*V,y+=(n=t[13])*j,g+=n*x,w+=n*O,p+=n*S,A+=n*$,M+=n*q,U+=n*z,m+=n*B,E+=n*C,T+=n*G,F+=n*H,I+=n*J,D+=n*N,K+=n*Q,L+=n*R,P+=n*V,g+=(n=t[14])*j,w+=n*x,p+=n*O,A+=n*S,M+=n*$,U+=n*q,m+=n*z,E+=n*B,T+=n*C,F+=n*G,I+=n*H,D+=n*J,K+=n*N,L+=n*Q,P+=n*R,X+=n*V,w+=(n=t[15])*j,u+=38*(A+=n*O),s+=38*(M+=n*S),a+=38*(U+=n*$),i+=38*(m+=n*q),v+=38*(E+=n*z),l+=38*(T+=n*B),_+=38*(F+=n*C),f+=38*(I+=n*G),d+=38*(D+=n*H),b+=38*(K+=n*J),h+=38*(L+=n*N),k+=38*(P+=n*Q),y+=38*(X+=n*R),g+=38*(Y+=n*V),o=(n=(o+=38*(p+=n*x))+(e=1)+65535)-65536*(e=Math.floor(n/65536)),u=(n=u+e+65535)-65536*(e=Math.floor(n/65536)),s=(n=s+e+65535)-65536*(e=Math.floor(n/65536)),a=(n=a+e+65535)-65536*(e=Math.floor(n/65536)),i=(n=i+e+65535)-65536*(e=Math.floor(n/65536)),v=(n=v+e+65535)-65536*(e=Math.floor(n/65536)),l=(n=l+e+65535)-65536*(e=Math.floor(n/65536)),_=(n=_+e+65535)-65536*(e=Math.floor(n/65536)),f=(n=f+e+65535)-65536*(e=Math.floor(n/65536)),d=(n=d+e+65535)-65536*(e=Math.floor(n/65536)),b=(n=b+e+65535)-65536*(e=Math.floor(n/65536)),h=(n=h+e+65535)-65536*(e=Math.floor(n/65536)),k=(n=k+e+65535)-65536*(e=Math.floor(n/65536)),y=(n=y+e+65535)-65536*(e=Math.floor(n/65536)),g=(n=g+e+65535)-65536*(e=Math.floor(n/65536)),w=(n=w+e+65535)-65536*(e=Math.floor(n/65536)),o=(n=(o+=e-1+37*(e-1))+(e=1)+65535)-65536*(e=Math.floor(n/65536)),u=(n=u+e+65535)-65536*(e=Math.floor(n/65536)),s=(n=s+e+65535)-65536*(e=Math.floor(n/65536)),a=(n=a+e+65535)-65536*(e=Math.floor(n/65536)),i=(n=i+e+65535)-65536*(e=Math.floor(n/65536)),v=(n=v+e+65535)-65536*(e=Math.floor(n/65536)),l=(n=l+e+65535)-65536*(e=Math.floor(n/65536)),_=(n=_+e+65535)-65536*(e=Math.floor(n/65536)),f=(n=f+e+65535)-65536*(e=Math.floor(n/65536)),d=(n=d+e+65535)-65536*(e=Math.floor(n/65536)),b=(n=b+e+65535)-65536*(e=Math.floor(n/65536)),h=(n=h+e+65535)-65536*(e=Math.floor(n/65536)),k=(n=k+e+65535)-65536*(e=Math.floor(n/65536)),y=(n=y+e+65535)-65536*(e=Math.floor(n/65536)),g=(n=g+e+65535)-65536*(e=Math.floor(n/65536)),w=(n=w+e+65535)-65536*(e=Math.floor(n/65536)),o+=e-1+37*(e-1),r[0]=o,r[1]=u,r[2]=s,r[3]=a,r[4]=i,r[5]=v,r[6]=l,r[7]=_,r[8]=f,r[9]=d,r[10]=b,r[11]=h,r[12]=k,r[13]=y,r[14]=g,r[15]=w}static blockround_dest(r,t){curve25519.blockround(r,t,t)}static inv25519(r,t){const c=curve25519.init_25519_constants();let n;for(n=0;n<16;n++)c[n]=t[n];for(n=253;n>=0;n--)curve25519.blockround_dest(c,c),2!==n&&4!==n&&curve25519.blockround(c,c,t);for(n=0;n<16;n++)r[n]=c[n]}static crypto_scalarmult(r,t,c){const n=new Uint8Array(32),e=new Float64Array(80);let o,u;const s=curve25519.init_25519_constants(),a=curve25519.init_25519_constants(),i=curve25519.init_25519_constants(),v=curve25519.init_25519_constants(),l=curve25519.init_25519_constants(),_=curve25519.init_25519_constants();for(u=0;u<31;u++)n[u]=t[u];for(n[31]=127&t[31]|64,n[0]&=248,curve25519.unpack25519(e,c),u=0;u<16;u++)a[u]=e[u],v[u]=s[u]=i[u]=0;for(s[0]=v[0]=1,u=254;u>=0;--u)o=n[u>>>3]>>>(7&u)&1,curve25519.sel25519(s,a,o),curve25519.sel25519(i,v,o),curve25519.blockadd(l,s,i),curve25519.blocksub(s,s,i),curve25519.blockadd(i,a,v),curve25519.blocksub(a,a,v),curve25519.blockround_dest(v,l),curve25519.blockround_dest(_,s),curve25519.blockround(s,i,s),curve25519.blockround(i,a,l),curve25519.blockadd(l,s,i),curve25519.blocksub(s,s,i),curve25519.blockround_dest(a,s),curve25519.blocksub(i,v,_),curve25519.blockround(s,i,curve25519._121665()),curve25519.blockadd(s,s,v),curve25519.blockround(i,i,s),curve25519.blockround(s,v,_),curve25519.blockround(v,a,e),curve25519.blockround_dest(a,l),curve25519.sel25519(s,a,o),curve25519.sel25519(i,v,o);for(u=0;u<16;u++)e[u+16]=s[u],e[u+32]=i[u],e[u+48]=a[u],e[u+64]=v[u];const f=e.subarray(32),d=e.subarray(16);return curve25519.inv25519(f,f),curve25519.blockround(d,d,f),curve25519.pack25519(r,d),0}static crypto_hash(r,t,c){function n(r,t,c,n){r[t]=c>>24&255,r[t+1]=c>>16&255,r[t+2]=c>>8&255,r[t+3]=255&c,r[t+4]=n>>24&255,r[t+5]=n>>16&255,r[t+6]=n>>8&255,r[t+7]=255&n}function e(r,t,c,n){const e=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591],o=new Int32Array(16),u=new Int32Array(16);let s,a,i,v,l,_,f,d,b,h,k,y,g,w,p,A,M,U,m,E,T,F,I,D,K,L,P=r[0],X=r[1],Y=r[2],j=r[3],x=r[4],O=r[5],S=r[6],$=r[7],q=t[0],z=t[1],B=t[2],C=t[3],G=t[4],H=t[5],J=t[6],N=t[7],Q=0;for(;n>=128;){for(m=0;m<16;m++)E=8*m+Q,o[m]=c[E+0]<<24|c[E+1]<<16|c[E+2]<<8|c[E+3],u[m]=c[E+4]<<24|c[E+5]<<16|c[E+6]<<8|c[E+7];for(m=0;m<80;m++)if(s=P,a=X,i=Y,v=j,l=x,_=O,f=S,d=$,b=q,h=z,k=B,y=C,g=G,w=H,p=J,A=N,I=65535&(F=N),D=F>>>16,K=65535&(T=$),L=T>>>16,I+=65535&(F=(G>>>14|x<<18)^(G>>>18|x<<14)^(x>>>9|G<<23)),D+=F>>>16,K+=65535&(T=(x>>>14|G<<18)^(x>>>18|G<<14)^(G>>>9|x<<23)),L+=T>>>16,I+=65535&(F=G&H^~G&J),D+=F>>>16,K+=65535&(T=x&O^~x&S),L+=T>>>16,I+=65535&(F=e[2*m+1]),D+=F>>>16,K+=65535&(T=e[2*m]),L+=T>>>16,T=o[m%16],D+=(F=u[m%16])>>>16,K+=65535&T,L+=T>>>16,K+=(D+=(I+=65535&F)>>>16)>>>16,I=65535&(F=U=65535&I|D<<16),D=F>>>16,K=65535&(T=M=65535&K|(L+=K>>>16)<<16),L=T>>>16,I+=65535&(F=(q>>>28|P<<4)^(P>>>2|q<<30)^(P>>>7|q<<25)),D+=F>>>16,K+=65535&(T=(P>>>28|q<<4)^(q>>>2|P<<30)^(q>>>7|P<<25)),L+=T>>>16,D+=(F=q&z^q&B^z&B)>>>16,K+=65535&(T=P&X^P&Y^X&Y),L+=T>>>16,d=65535&(K+=(D+=(I+=65535&F)>>>16)>>>16)|(L+=K>>>16)<<16,A=65535&I|D<<16,I=65535&(F=y),D=F>>>16,K=65535&(T=v),L=T>>>16,D+=(F=U)>>>16,K+=65535&(T=M),L+=T>>>16,X=s,Y=a,j=i,x=v=65535&(K+=(D+=(I+=65535&F)>>>16)>>>16)|(L+=K>>>16)<<16,O=l,S=_,$=f,P=d,z=b,B=h,C=k,G=y=65535&I|D<<16,H=g,J=w,N=p,q=A,m%16==15)for(E=0;E<16;E++)T=o[E],I=65535&(F=u[E]),D=F>>>16,K=65535&T,L=T>>>16,T=o[(E+9)%16],I+=65535&(F=u[(E+9)%16]),D+=F>>>16,K+=65535&T,L+=T>>>16,M=o[(E+1)%16],I+=65535&(F=((U=u[(E+1)%16])>>>1|M<<31)^(U>>>8|M<<24)^(U>>>7|M<<25)),D+=F>>>16,K+=65535&(T=(M>>>1|U<<31)^(M>>>8|U<<24)^M>>>7),L+=T>>>16,M=o[(E+14)%16],D+=(F=((U=u[(E+14)%16])>>>19|M<<13)^(M>>>29|U<<3)^(U>>>6|M<<26))>>>16,K+=65535&(T=(M>>>19|U<<13)^(U>>>29|M<<3)^M>>>6),L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,o[E]=65535&K|L<<16,u[E]=65535&I|D<<16;I=65535&(F=q),D=F>>>16,K=65535&(T=P),L=T>>>16,T=r[0],D+=(F=t[0])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[0]=P=65535&K|L<<16,t[0]=q=65535&I|D<<16,I=65535&(F=z),D=F>>>16,K=65535&(T=X),L=T>>>16,T=r[1],D+=(F=t[1])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[1]=X=65535&K|L<<16,t[1]=z=65535&I|D<<16,I=65535&(F=B),D=F>>>16,K=65535&(T=Y),L=T>>>16,T=r[2],D+=(F=t[2])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[2]=Y=65535&K|L<<16,t[2]=B=65535&I|D<<16,I=65535&(F=C),D=F>>>16,K=65535&(T=j),L=T>>>16,T=r[3],D+=(F=t[3])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[3]=j=65535&K|L<<16,t[3]=C=65535&I|D<<16,I=65535&(F=G),D=F>>>16,K=65535&(T=x),L=T>>>16,T=r[4],D+=(F=t[4])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[4]=x=65535&K|L<<16,t[4]=G=65535&I|D<<16,I=65535&(F=H),D=F>>>16,K=65535&(T=O),L=T>>>16,T=r[5],D+=(F=t[5])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[5]=O=65535&K|L<<16,t[5]=H=65535&I|D<<16,I=65535&(F=J),D=F>>>16,K=65535&(T=S),L=T>>>16,T=r[6],D+=(F=t[6])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[6]=S=65535&K|L<<16,t[6]=J=65535&I|D<<16,I=65535&(F=N),D=F>>>16,K=65535&(T=$),L=T>>>16,T=r[7],D+=(F=t[7])>>>16,K+=65535&T,L+=T>>>16,L+=(K+=(D+=(I+=65535&F)>>>16)>>>16)>>>16,r[7]=$=65535&K|L<<16,t[7]=N=65535&I|D<<16,Q+=128,n-=128}return n}const o=new Int32Array(8),u=new Int32Array(8),s=new Uint8Array(256);let a;const i=c;for(o[0]=1779033703,o[1]=3144134277,o[2]=1013904242,o[3]=2773480762,o[4]=1359893119,o[5]=2600822924,o[6]=528734635,o[7]=1541459225,u[0]=4089235720,u[1]=2227873595,u[2]=4271175723,u[3]=1595750129,u[4]=2917565137,u[5]=725511199,u[6]=4215389547,u[7]=327033209,e(o,u,t,c),c%=128,a=0;a<c;a++)s[a]=t[i-c+a];for(s[c]=128,s[(c=256-128*(c<112?1:0))-9]=0,n(s,c-8,i/536870912|0,i<<3),e(o,u,s,c),a=0;a<8;a++)n(r,8*a,o[a],u[a]);return 0}static add(r,t){const c=curve25519.init_25519_constants(),n=curve25519.init_25519_constants(),e=curve25519.init_25519_constants(),o=curve25519.init_25519_constants(),u=curve25519.init_25519_constants(),s=curve25519.init_25519_constants(),a=curve25519.init_25519_constants(),i=curve25519.init_25519_constants(),v=curve25519.init_25519_constants();curve25519.blocksub(c,r[1],r[0]),curve25519.blocksub(v,t[1],t[0]),curve25519.blockround(c,c,v),curve25519.blockadd(n,r[0],r[1]),curve25519.blockadd(v,t[0],t[1]),curve25519.blockround(n,n,v),curve25519.blockround(e,r[3],t[3]),curve25519.blockround(e,e,curve25519.D2()),curve25519.blockround(o,r[2],t[2]),curve25519.blockadd(o,o,o),curve25519.blocksub(u,n,c),curve25519.blocksub(s,o,e),curve25519.blockadd(a,o,e),curve25519.blockadd(i,n,c),curve25519.blockround(r[0],u,s),curve25519.blockround(r[1],i,a),curve25519.blockround(r[2],a,s),curve25519.blockround(r[3],u,i)}static pack(r,t){const c=curve25519.init_25519_constants(),n=curve25519.init_25519_constants(),e=curve25519.init_25519_constants();curve25519.inv25519(e,t[2]),curve25519.blockround(c,t[0],e),curve25519.blockround(n,t[1],e),curve25519.pack25519(r,n),r[31]^=curve25519.par25519(c)<<7}static scalarmult(r,t,c){function n(r,t,c){let n;for(n=0;n<4;n++)curve25519.sel25519(r[n],t[n],c)}let e,o;for(curve25519.set25519(r[0],curve25519.gf0()),curve25519.set25519(r[1],curve25519.gf1()),curve25519.set25519(r[2],curve25519.gf1()),curve25519.set25519(r[3],curve25519.gf0()),o=255;o>=0;--o)n(r,t,e=c[o/8|0]>>(7&o)&1),add(t,r),add(r,r),n(r,t,e)}static scalarbase(r,t){const c=[curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants()];curve25519.set25519(c[0],curve25519.X()),curve25519.set25519(c[1],curve25519.Y()),curve25519.set25519(c[2],curve25519.gf1()),curve25519.blockround(c[3],curve25519.X(),curve25519.Y()),curve25519.scalarmult(r,c,t)}static modL(r,t){const c=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);let n,e,o,u;for(e=63;e>=32;--e){for(n=0,o=e-32,u=e-12;o<u;++o)t[o]+=n-16*t[e]*c[o-(e-32)],n=t[o]+128>>8,t[o]-=256*n;t[o]+=n,t[e]=0}for(n=0,o=0;o<32;o++)t[o]+=n-(t[31]>>4)*c[o],n=t[o]>>8,t[o]&=255;for(o=0;o<32;o++)t[o]-=n*c[o];for(e=0;e<32;e++)t[e+1]+=t[e]>>8,r[e]=255&t[e]}static reduce(r){const t=new Float64Array(64);let c;for(c=0;c<64;c++)t[c]=r[c];for(c=0;c<64;c++)r[c]=0;curve25519.modL(r,t)}static curve25519_sign(r,t,c,n,e){function o(r,t,c,n){const e=new Uint8Array(64),o=new Uint8Array(64);let u,s;const a=new Float64Array(64),i=[curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants()];for(u=0;u<c;u++)r[64+u]=t[u];for(u=0;u<32;u++)r[32+u]=n[u];for(curve25519.crypto_hash(o,r.subarray(32),c+32),curve25519.reduce(o),curve25519.scalarbase(i,o),curve25519.pack(r,i),u=0;u<32;u++)r[u+32]=n[32+u];for(curve25519.crypto_hash(e,r,c+64),curve25519.reduce(e),u=0;u<64;u++)a[u]=0;for(u=0;u<32;u++)a[u]=o[u];for(u=0;u<32;u++)for(s=0;s<32;s++)a[u+s]+=e[u]*n[s];return curve25519.modL(r.subarray(32),a),c+64}function u(r,t,c,n,e){const o=new Uint8Array(64),u=new Uint8Array(64);let s,a;const i=new Float64Array(64),v=[curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants()];for(r[0]=254,s=1;s<32;s++)r[s]=255;for(s=0;s<32;s++)r[32+s]=n[s];for(s=0;s<c;s++)r[64+s]=t[s];for(s=0;s<64;s++)r[c+64+s]=e[s];for(curve25519.crypto_hash(u,r,c+128),curve25519.reduce(u),curve25519.scalarbase(v,u),curve25519.pack(r,v),s=0;s<32;s++)r[s+32]=n[32+s];for(curve25519.crypto_hash(o,r,c+64),curve25519.reduce(o),s=0;s<64;s++)r[c+64+s]=0;for(s=0;s<64;s++)i[s]=0;for(s=0;s<32;s++)i[s]=u[s];for(s=0;s<32;s++)for(a=0;a<32;a++)i[s+a]+=o[s]*n[a];return curve25519.modL(r.subarray(32,c+64),i),c+64}const s=new Uint8Array(64),a=[curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants()];for(let r=0;r<32;r++)s[r]=n[r];s[0]&=248,s[31]&=127,s[31]|=64,curve25519.scalarbase(a,s),curve25519.pack(s.subarray(32),a);const i=128&s[63];let v;return v=e?u(r,t,c,s,e):o(r,t,c,s),r[63]|=i,v}static convertPublicKey(r){const t=new Uint8Array(32),c=curve25519.init_25519_constants(),n=curve25519.init_25519_constants(),e=curve25519.init_25519_constants();return curve25519.unpack25519(c,r),curve25519.blockadd(n,c,curve25519.gf1()),curve25519.blocksub(e,c,curve25519.gf1()),curve25519.inv25519(n,n),curve25519.blockround(n,n,e),curve25519.pack25519(t,n),t}static curve25519_sign_open(r,t,c,n){function e(r,t,c,n){function e(r,t){function c(r,t){const c=new Uint8Array(32),n=new Uint8Array(32);return curve25519.pack25519(c,r),curve25519.pack25519(n,t),curve25519.crypto_verify_32(c,0,n,0)}function n(r,t){const c=curve25519.init_25519_constants();let n;for(n=0;n<16;n++)c[n]=t[n];for(n=250;n>=0;n--)curve25519.blockround_dest(c,c),1!==n&&curve25519.blockround(c,c,t);for(n=0;n<16;n++)r[n]=c[n]}const e=curve25519.init_25519_constants(),o=curve25519.init_25519_constants(),u=curve25519.init_25519_constants(),s=curve25519.init_25519_constants(),a=curve25519.init_25519_constants(),i=curve25519.init_25519_constants(),v=curve25519.init_25519_constants();return curve25519.set25519(r[2],curve25519.gf1()),curve25519.unpack25519(r[1],t),curve25519.blockround_dest(u,r[1]),curve25519.blockround(s,u,curve25519.D()),curve25519.blocksub(u,u,r[2]),curve25519.blockadd(s,r[2],s),curve25519.blockround_dest(a,s),curve25519.blockround_dest(i,a),curve25519.blockround(v,i,a),curve25519.blockround(e,v,u),curve25519.blockround(e,e,s),n(e,e),curve25519.blockround(e,e,u),curve25519.blockround(e,e,s),curve25519.blockround(e,e,s),curve25519.blockround(r[0],e,s),curve25519.blockround_dest(o,r[0]),curve25519.blockround(o,o,s),c(o,u)&&curve25519.blockround(r[0],r[0],curve25519.I()),curve25519.blockround_dest(o,r[0]),curve25519.blockround(o,o,s),c(o,u)?-1:(curve25519.par25519(r[0])===t[31]>>7&&curve25519.blocksub(r[0],curve25519.gf0(),r[0]),curve25519.blockround(r[3],r[0],r[1]),0)}let o,u;const s=new Uint8Array(32),a=new Uint8Array(64),i=[curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants()],v=[curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants(),curve25519.init_25519_constants()];if(c<64)return-1;if(e(v,n))return-1;for(o=0;o<c;o++)r[o]=t[o];for(o=0;o<32;o++)r[o+32]=n[o];if(curve25519.crypto_hash(a,r,c),curve25519.reduce(a),curve25519.scalarmult(i,v,a),curve25519.scalarbase(v,t.subarray(32)),add(i,v),curve25519.pack(s,i),c-=64,curve25519.crypto_verify_32(t,0,s,0)){for(o=0;o<c;o++)r[o]=0;return-1}for(o=0;o<c;o++)r[o]=t[o+64];return u=c}const o=curve25519.convertPublicKey(n);return o[31]|=128&t[63],t[63]&=127,e(r,t,c,o)}static sharedKey(r,t){if(curve25519.checkArrayTypes(t,r),32!==t.length)throw new Error(\"wrong public key length\");if(32!==r.length)throw new Error(\"wrong secret key length\");const c=new Uint8Array(32);return curve25519.crypto_scalarmult(c,r,t),c}static signMessage(r,t,c){if(curve25519.checkArrayTypes(t,r),32!==r.length)throw new Error(\"wrong secret key length\");if(c){if(curve25519.checkArrayTypes(c),64!==c.length)throw new Error(\"wrong random data length\");const n=new Uint8Array(128+t.length);return curve25519.curve25519_sign(n,t,t.length,r,c),new Uint8Array(n.subarray(0,64+t.length))}{const c=new Uint8Array(64+t.length);return curve25519.curve25519_sign(c,t,t.length,r),c}}static openMessage(r,t){if(curve25519.checkArrayTypes(t,r),32!==r.length)throw new Error(\"wrong public key length\");const c=new Uint8Array(t.length),n=curve25519.curve25519_sign_open(c,t,t.length,r);if(n<0)return null;const e=new Uint8Array(n);for(let r=0;r<e.length;r++)e[r]=c[r];return e}static sign(r,t,c){if(curve25519.checkArrayTypes(r,t),32!==r.length)throw new Error(\"wrong secret key length\");if(c&&(curve25519.checkArrayTypes(c),64!==c.length))throw new Error(\"wrong random data length\");const n=new Uint8Array((c?128:64)+t.length);curve25519.curve25519_sign(n,t,t.length,r,c);const e=new Uint8Array(64);for(let r=0;r<e.length;r++)e[r]=n[r];return e}static verify(r,t,c){if(curve25519.checkArrayTypes(t,c,r),64!==c.length)throw new Error(\"wrong signature length\");if(32!==r.length)throw new Error(\"wrong public key length\");const n=new Uint8Array(64+t.length),e=new Uint8Array(64+t.length);for(let r=0;r<64;r++)n[r]=c[r];for(let r=0;r<t.length;r++)n[r+64]=t[r];return curve25519.curve25519_sign_open(e,n,n.length,r)>=0}static generateKeyPair(r){function t(r,t){const c=new Uint8Array(32);return c[0]=9,curve25519.crypto_scalarmult(r,t,c)}if(curve25519.checkArrayTypes(r),32!==r.length)throw new Error(\"wrong seed length\");const c=new Uint8Array(32),n=new Uint8Array(32);for(let t=0;t<32;t++)c[t]=r[t];return t(n,c),c[0]&=248,c[31]&=127,c[31]|=64,n[31]&=127,{public:n,private:c}}}\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIjAiXSwibmFtZXMiOlsiY3VydmUyNTUxOSIsIltvYmplY3QgT2JqZWN0XSIsImluaXQiLCJyIiwiRmxvYXQ2NEFycmF5IiwiaSIsImxlbmd0aCIsImluaXRfMjU1MTlfY29uc3RhbnRzIiwidCIsImFyZ3VtZW50cyIsIk9iamVjdCIsInByb3RvdHlwZSIsInRvU3RyaW5nIiwiY2FsbCIsIlR5cGVFcnJvciIsIngiLCJ4aSIsInkiLCJ5aSIsInZuIiwibiIsImQiLCJhIiwicCIsInEiLCJiIiwiYyIsIm8iLCJjYXIyNTUxOSIsInYiLCJNYXRoIiwiZmxvb3IiLCJqIiwibSIsInNlbDI1NTE5IiwiVWludDhBcnJheSIsInBhY2syNTUxOSIsInQwIiwidDEiLCJ0MiIsInQzIiwidDQiLCJ0NSIsInQ2IiwidDciLCJ0OCIsInQ5IiwidDEwIiwidDExIiwidDEyIiwidDEzIiwidDE0IiwidDE1IiwidDE2IiwidDE3IiwidDE4IiwidDE5IiwidDIwIiwidDIxIiwidDIyIiwidDIzIiwidDI0IiwidDI1IiwidDI2IiwidDI3IiwidDI4IiwidDI5IiwidDMwIiwiYjAiLCJiMSIsImIyIiwiYjMiLCJiNCIsImI1IiwiYjYiLCJiNyIsImI4IiwiYjkiLCJiMTAiLCJiMTEiLCJiMTIiLCJiMTMiLCJiMTQiLCJiMTUiLCJibG9ja3JvdW5kIiwiYmxvY2tyb3VuZF9kZXN0IiwieiIsImUiLCJmIiwidW5wYWNrMjU1MTkiLCJibG9ja2FkZCIsImJsb2Nrc3ViIiwiXzEyMTY2NSIsIngzMiIsInN1YmFycmF5IiwieDE2IiwiaW52MjU1MTkiLCJvdXQiLCJ0czY0IiwiaCIsImwiLCJjcnlwdG9faGFzaGJsb2Nrc19obCIsImhoIiwiaGwiLCJLIiwid2giLCJJbnQzMkFycmF5Iiwid2wiLCJiaDAiLCJiaDEiLCJiaDIiLCJiaDMiLCJiaDQiLCJiaDUiLCJiaDYiLCJiaDciLCJibDAiLCJibDEiLCJibDIiLCJibDMiLCJibDQiLCJibDUiLCJibDYiLCJibDciLCJ0aCIsInRsIiwiYWgwIiwiYWgxIiwiYWgyIiwiYWgzIiwiYWg0IiwiYWg1IiwiYWg2IiwiYWg3IiwiYWwwIiwiYWwxIiwiYWwyIiwiYWwzIiwiYWw0IiwiYWw1IiwiYWw2IiwiYWw3IiwicG9zIiwiZyIsIkQyIiwidHgiLCJ0eSIsInppIiwicGFyMjU1MTkiLCJzIiwiY3N3YXAiLCJzZXQyNTUxOSIsImdmMCIsImdmMSIsImFkZCIsIlgiLCJZIiwic2NhbGFybXVsdCIsIkwiLCJjYXJyeSIsImsiLCJtb2RMIiwic20iLCJzayIsIm9wdF9ybmQiLCJjcnlwdG9fc2lnbl9kaXJlY3QiLCJjcnlwdG9faGFzaCIsInJlZHVjZSIsInNjYWxhcmJhc2UiLCJwYWNrIiwiY3J5cHRvX3NpZ25fZGlyZWN0X3JuZCIsInJuZCIsImVkc2siLCJzaWduQml0Iiwic21sZW4iLCJwayIsImNyeXB0b19zaWduX29wZW4iLCJ1bnBhY2tuZWciLCJuZXEyNTUxOSIsImNyeXB0b192ZXJpZnlfMzIiLCJwb3cyNTIzIiwiY2hrIiwibnVtIiwiZGVuIiwiZGVuMiIsImRlbjQiLCJkZW42IiwiRCIsIkkiLCJtbGVuIiwiZWRwayIsImNvbnZlcnRQdWJsaWNLZXkiLCJzZWNyZXRLZXkiLCJwdWJsaWNLZXkiLCJjaGVja0FycmF5VHlwZXMiLCJFcnJvciIsInNoYXJlZEtleSIsImNyeXB0b19zY2FsYXJtdWx0IiwibXNnIiwib3B0X3JhbmRvbSIsImJ1ZiIsImN1cnZlMjU1MTlfc2lnbiIsInNpZ25lZE1zZyIsInRtcCIsImxlbiIsImN1cnZlMjU1MTlfc2lnbl9vcGVuIiwic2lnbmF0dXJlIiwic2VlZCIsImNyeXB0b19zY2FsYXJtdWx0X2Jhc2UiLCJfOSIsInB1YmxpYyIsInByaXZhdGUiXSwibWFwcGluZ3MiOiJBQTBCQSxtQkFrQk1BLFdBRUZDLDRCQUE2QkMsR0FDekIsTUFBTUMsRUFBSSxJQUFJQyxhQUFjLElBRTVCLEdBQUtGLEVBQ0QsSUFBTSxJQUFJRyxFQUFJLEVBQUdBLEVBQUlILEVBQUtJLE9BQVFELElBQzlCRixFQUFHRSxHQUFN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"},
            'sjcl.js': {"requiresElectron":true,"requiresBrowser":false,"code":"\"use strict\";function r(t){throw t}var s=void 0,v=!1;function H(){return function(){}}var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt(t){this.toString=function(){return\"CORRUPT: \"+this.message},this.message=t},invalid(t){this.toString=function(){return\"INVALID: \"+this.message},this.message=t},bug(t){this.toString=function(){return\"BUG: \"+this.message},this.message=t},notReady(t){this.toString=function(){return\"NOT READY: \"+this.message},this.message=t}}},a;function aa(t,e,i){4!==e.length&&r(new sjcl.exception.invalid(\"invalid aes block size\"));var s=t.b[i],n=e[0]^s[0],a=e[i?3:1]^s[1],c=e[2]^s[2];e=e[i?1:3]^s[3];var o,h,l,u=s.length/4-2,f,d=4,p=[0,0,0,0];t=(o=t.l[i])[0];var y=o[1],g=o[2],m=o[3],b=o[4];for(f=0;f<u;f++)o=t[n>>>24]^y[a>>16&255]^g[c>>8&255]^m[255&e]^s[d],h=t[a>>>24]^y[c>>16&255]^g[e>>8&255]^m[255&n]^s[d+1],l=t[c>>>24]^y[e>>16&255]^g[n>>8&255]^m[255&a]^s[d+2],e=t[e>>>24]^y[n>>16&255]^g[a>>8&255]^m[255&c]^s[d+3],d+=4,n=o,a=h,c=l;for(f=0;4>f;f++)p[i?3&-f:f]=b[n>>>24]<<24^b[a>>16&255]<<16^b[c>>8&255]<<8^b[255&e]^s[d++],o=n,n=a,a=c,c=e,e=o;return p}function da(t,e){var r,i=sjcl.random.A[t],s=[];for(r in i)i.hasOwnProperty(r)&&s.push(i[r]);for(r=0;r<s.length;r++)s[r](e)}function Q(t){\"undefined\"!=typeof window&&window.performance&&\"function\"==typeof window.performance.now?sjcl.random.addEntropy(window.performance.now(),t,\"loadtime\"):sjcl.random.addEntropy((new Date).valueOf(),t,\"loadtime\")}function ba(t){t.b=ca(t).concat(ca(t)),t.B=new sjcl.cipher.aes(t.b)}function ca(t){for(var e=0;4>e&&(t.h[e]=t.h[e]+1|0,!t.h[e]);e++);return t.B.encrypt(t.h)}function P(t,e){return function(){e.apply(t,arguments)}}\"undefined\"!=typeof module&&module.exports&&(module.exports=sjcl),\"function\"==typeof define&&define([],function(){return sjcl}),sjcl.cipher.aes=function(t){this.l[0][0][0]||this.q();var e,i,s,n,a=this.l[0][4],c=this.l[1],o=1;for(4!==(e=t.length)&&6!==e&&8!==e&&r(new sjcl.exception.invalid(\"invalid aes key size\")),this.b=[s=t.slice(0),n=[]],t=e;t<4*e+28;t++)i=s[t-1],(0==t%e||8===e&&4==t%e)&&(i=a[i>>>24]<<24^a[i>>16&255]<<16^a[i>>8&255]<<8^a[255&i],0==t%e&&(i=i<<8^i>>>24^o<<24,o=o<<1^283*(o>>7))),s[t]=s[t-e]^i;for(e=0;t;e++,t--)i=s[3&e?t:t-4],n[e]=4>=t||4>e?i:c[0][a[i>>>24]]^c[1][a[i>>16&255]]^c[2][a[i>>8&255]]^c[3][a[255&i]]},sjcl.cipher.aes.prototype={encrypt(t){return aa(this,t,0)},decrypt(t){return aa(this,t,1)},l:[[[],[],[],[],[]],[[],[],[],[],[]]],q(){var t=this.l[0],e=this.l[1],r=t[4],i=e[4],s,n,a,c=[],o=[],h,l,u,f;for(s=0;256>s;s++)o[(c[s]=s<<1^283*(s>>7))^s]=s;for(n=a=0;!r[n];n^=h||1,a=o[a]||1)for(u=(u=a^a<<1^a<<2^a<<3^a<<4)>>8^255&u^99,r[n]=u,i[u]=n,f=16843009*(l=c[s=c[h=c[n]]])^65537*s^257*h^16843008*n,l=257*c[u]^16843008*u,s=0;4>s;s++)t[s][n]=l=l<<24^l>>>8,e[s][u]=f=f<<24^f>>>8;for(s=0;5>s;s++)t[s]=t[s].slice(0),e[s]=e[s].slice(0)}},sjcl.bitArray={bitSlice(t,e,r){return t=sjcl.bitArray.M(t.slice(e/32),32-(31&e)).slice(1),r===s?t:sjcl.bitArray.clamp(t,r-e)},extract(t,e,r){var i=Math.floor(-e-r&31);return(-32&(e+r-1^e)?t[e/32|0]<<32-i^t[e/32+1|0]>>>i:t[e/32|0]>>>i)&(1<<r)-1},concat(t,e){if(0===t.length||0===e.length)return t.concat(e);var r=t[t.length-1],i=sjcl.bitArray.getPartial(r);return 32===i?t.concat(e):sjcl.bitArray.M(e,i,0|r,t.slice(0,t.length-1))},bitLength(t){var e=t.length;return 0===e?0:32*(e-1)+sjcl.bitArray.getPartial(t[e-1])},clamp(t,e){if(32*t.length<e)return t;var r=(t=t.slice(0,Math.ceil(e/32))).length;return e&=31,0<r&&e&&(t[r-1]=sjcl.bitArray.partial(e,t[r-1]&2147483648>>e-1,1)),t},partial(t,e,r){return 32===t?e:(r?0|e:e<<32-t)+1099511627776*t},getPartial(t){return Math.round(t/1099511627776)||32},equal(t,e){if(sjcl.bitArray.bitLength(t)!==sjcl.bitArray.bitLength(e))return v;var r=0,i;for(i=0;i<t.length;i++)r|=t[i]^e[i];return 0===r},M(t,e,r,i){var n;for(n=0,i===s&&(i=[]);32<=e;e-=32)i.push(r),r=0;if(0===e)return i.concat(t);for(n=0;n<t.length;n++)i.push(r|t[n]>>>e),r=t[n]<<32-e;return n=t.length?t[t.length-1]:0,t=sjcl.bitArray.getPartial(n),i.push(sjcl.bitArray.partial(e+t&31,32<e+t?r:i.pop(),1)),i},u(t,e){return[t[0]^e[0],t[1]^e[1],t[2]^e[2],t[3]^e[3]]},byteswapM(t){var e,r;for(e=0;e<t.length;++e)r=t[e],t[e]=r>>>24|r>>>8&65280|(65280&r)<<8|r<<24;return t}},sjcl.codec.utf8String={fromBits(t){var e=\"\",r=sjcl.bitArray.bitLength(t),i,s;for(i=0;i<r/8;i++)0==(3&i)&&(s=t[i/4]),e+=String.fromCharCode(s>>>24),s<<=8;return decodeURIComponent(escape(e))},toBits(t){t=unescape(encodeURIComponent(t));var e=[],r,i=0;for(r=0;r<t.length;r++)i=i<<8|t.charCodeAt(r),3==(3&r)&&(e.push(i),i=0);return 3&r&&e.push(sjcl.bitArray.partial(8*(3&r),i)),e}},sjcl.codec.base64={I:\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\",fromBits(t,e,r){var i=\"\",s=0,n=sjcl.codec.base64.I,a=0,c=sjcl.bitArray.bitLength(t);for(r&&(n=n.substr(0,62)+\"-_\"),r=0;6*i.length<c;)i+=n.charAt((a^t[r]>>>s)>>>26),6>s?(a=t[r]<<6-s,s+=26,r++):(a<<=6,s-=6);for(;3&i.length&&!e;)i+=\"=\";return i},toBits(t,e){t=t.replace(/\\s|=/g,\"\");var i=[],s,n=0,a=sjcl.codec.base64.I,c=0,o;for(e&&(a=a.substr(0,62)+\"-_\"),s=0;s<t.length;s++)0>(o=a.indexOf(t.charAt(s)))&&r(new sjcl.exception.invalid(\"this isn't base64!\")),26<n?(n-=26,i.push(c^o>>>n),c=o<<32-n):c^=o<<32-(n+=6);return 56&n&&i.push(sjcl.bitArray.partial(56&n,c,1)),i}},sjcl.codec.base64url={fromBits(t){return sjcl.codec.base64.fromBits(t,1,1)},toBits(t){return sjcl.codec.base64.toBits(t,1)}},sjcl.codec.bytes={fromBits(t){var e=[],r=sjcl.bitArray.bitLength(t),i,s;for(i=0;i<r/8;i++)0==(3&i)&&(s=t[i/4]),e.push(s>>>24),s<<=8;return e},toBits(t){var e=[],r,i=0;for(r=0;r<t.length;r++)i=i<<8|t[r],3==(3&r)&&(e.push(i),i=0);return 3&r&&e.push(sjcl.bitArray.partial(8*(3&r),i)),e}},sjcl.hash.sha256=function(t){this.b[0]||this.q(),t?(this.e=t.e.slice(0),this.d=t.d.slice(0),this.c=t.c):this.reset()},sjcl.hash.sha256.hash=function(t){return(new sjcl.hash.sha256).update(t).finalize()},sjcl.hash.sha256.prototype={blockSize:512,reset(){return this.e=this.i.slice(0),this.d=[],this.c=0,this},update(t){\"string\"==typeof t&&(t=sjcl.codec.utf8String.toBits(t));var e,r=this.d=sjcl.bitArray.concat(this.d,t);for(e=this.c,t=this.c=e+sjcl.bitArray.bitLength(t),e=512+e&-512;e<=t;e+=512)this.n(r.splice(0,16));return this},finalize(){var t,e=this.d,r=this.e,e;for(t=(e=sjcl.bitArray.concat(e,[sjcl.bitArray.partial(1,1)])).length+2;15&t;t++)e.push(0);for(e.push(Math.floor(this.c/4294967296)),e.push(0|this.c);e.length;)this.n(e.splice(0,16));return this.reset(),r},i:[],b:[],q(){function t(t){return 4294967296*(t-Math.floor(t))|0}var e=0,r=2,i;t:for(;64>e;r++){for(i=2;i*i<=r;i++)if(0==r%i)continue t;8>e&&(this.i[e]=t(Math.pow(r,.5))),this.b[e]=t(Math.pow(r,1/3)),e++}},n(t){var e,r,i=t.slice(0),s=this.e,n=this.b,a=s[0],c=s[1],o=s[2],h=s[3],l=s[4],u=s[5],f=s[6],d=s[7];for(t=0;64>t;t++)16>t?e=i[t]:(e=i[t+1&15],r=i[t+14&15],e=i[15&t]=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(r>>>17^r>>>19^r>>>10^r<<15^r<<13)+i[15&t]+i[t+9&15]|0),e=e+d+(l>>>6^l>>>11^l>>>25^l<<26^l<<21^l<<7)+(f^l&(u^f))+n[t],d=f,f=u,u=l,l=h+e|0,h=o,o=c,a=e+((c=a)&o^h&(c^o))+(c>>>2^c>>>13^c>>>22^c<<30^c<<19^c<<10)|0;s[0]=s[0]+a|0,s[1]=s[1]+c|0,s[2]=s[2]+o|0,s[3]=s[3]+h|0,s[4]=s[4]+l|0,s[5]=s[5]+u|0,s[6]=s[6]+f|0,s[7]=s[7]+d|0}},sjcl.hash.sha512=function(t){this.b[0]||this.q(),t?(this.e=t.e.slice(0),this.d=t.d.slice(0),this.c=t.c):this.reset()},sjcl.hash.sha512.hash=function(t){return(new sjcl.hash.sha512).update(t).finalize()},sjcl.hash.sha512.prototype={blockSize:1024,reset(){return this.e=this.i.slice(0),this.d=[],this.c=0,this},update(t){\"string\"==typeof t&&(t=sjcl.codec.utf8String.toBits(t));var e,r=this.d=sjcl.bitArray.concat(this.d,t);for(e=this.c,t=this.c=e+sjcl.bitArray.bitLength(t),e=1024+e&-1024;e<=t;e+=1024)this.n(r.splice(0,32));return this},finalize(){var t,e=this.d,r=this.e,e;for(t=(e=sjcl.bitArray.concat(e,[sjcl.bitArray.partial(1,1)])).length+4;31&t;t++)e.push(0);for(e.push(0),e.push(0),e.push(Math.floor(this.c/4294967296)),e.push(0|this.c);e.length;)this.n(e.splice(0,32));return this.reset(),r},i:[],T:[12372232,13281083,9762859,1914609,15106769,4090911,4308331,8266105],b:[],V:[2666018,15689165,5061423,9034684,4764984,380953,1658779,7176472,197186,7368638,14987916,16757986,8096111,1480369,13046325,6891156,15813330,5187043,9229749,11312229,2818677,10937475,4324308,1135541,6741931,11809296,16458047,15666916,11046850,698149,229999,945776,13774844,2541862,12856045,9810911,11494366,7844520,15576806,8533307,15795044,4337665,16291729,5553712,15684120,6662416,7413802,12308920,13816008,4303699,9366425,10176680,13195875,4295371,6546291,11712675,15708924,1519456,15772530,6568428,6495784,8568297,13007125,7492395,2515356,12632583,14740254,7262584,1535930,13146278,16321966,1853211,294276,13051027,13221564,1051980,4080310,6651434,14088940,4675607],q(){function t(t){return 4294967296*(t-Math.floor(t))|0}function e(t){return 1099511627776*(t-Math.floor(t))&255}var r=0,i=2,s;t:for(;80>r;i++){for(s=2;s*s<=i;s++)if(0==i%s)continue t;8>r&&(this.i[2*r]=t(Math.pow(i,.5)),this.i[2*r+1]=e(Math.pow(i,.5))<<24|this.T[r]),this.b[2*r]=t(Math.pow(i,1/3)),this.b[2*r+1]=e(Math.pow(i,1/3))<<24|this.V[r],r++}},n(t){var e,r,i=t.slice(0),s=this.e,n=this.b,a=s[0],c=s[1],o=s[2],h=s[3],l=s[4],u=s[5],f=s[6],d=s[7],p=s[8],y=s[9],g=s[10],m=s[11],b=s[12],v=s[13],j=s[14],w=s[15],A=a,L=c,B=o,C=h,E=l,U=u,k=f,x=d,V=p,M=y,S=g,D=m,P=b,R=v,O=j,z=w;for(t=0;80>t;t++){if(16>t)e=i[2*t],r=i[2*t+1];else{var I;r=i[2*(t-15)],e=((I=i[2*(t-15)+1])<<31|r>>>1)^(I<<24|r>>>8)^r>>>7;var T=(r<<31|I>>>1)^(r<<24|I>>>8)^(r<<25|I>>>7);r=i[2*(t-2)];var q,I=((q=i[2*(t-2)+1])<<13|r>>>19)^(r<<3|q>>>29)^r>>>6,q=(r<<13|q>>>19)^(q<<3|r>>>29)^(r<<26|q>>>6),G=i[2*(t-7)],Q=i[2*(t-16)],W=i[2*(t-16)+1];e=e+G+((r=T+i[2*(t-7)+1])>>>0<T>>>0?1:0),e+=I+((r+=q)>>>0<q>>>0?1:0),e+=Q+((r+=W)>>>0<W>>>0?1:0)}i[2*t]=e|=0,i[2*t+1]=r|=0;var G=V&S^~V&P,Y=M&D^~M&R,q=A&B^A&E^B&E,X=L&C^L&U^C&U,Q=(L<<4|A>>>28)^(A<<30|L>>>2)^(A<<25|L>>>7),W=(A<<4|L>>>28)^(L<<30|A>>>2)^(L<<25|A>>>7),_=n[2*t],F=n[2*t+1],I,T,I,T,I,T,I,T=(T=(T=(T=O+((M<<18|V>>>14)^(M<<14|V>>>18)^(V<<23|M>>>9))+((I=z+((V<<18|M>>>14)^(V<<14|M>>>18)^(M<<23|V>>>9)))>>>0<z>>>0?1:0))+(G+((I=I+Y)>>>0<Y>>>0?1:0)))+(_+((I=I+F)>>>0<F>>>0?1:0)))+(e+((I=I+r|0)>>>0<r>>>0?1:0));e=Q+q+((r=W+X)>>>0<W>>>0?1:0),O=P,z=R,P=S,R=D,S=V,D=M,V=k+T+((M=x+I|0)>>>0<x>>>0?1:0)|0,k=E,x=U,E=B,U=C,B=A,C=L,A=T+e+((L=I+r|0)>>>0<I>>>0?1:0)|0}c=s[1]=c+L|0,s[0]=a+A+(c>>>0<L>>>0?1:0)|0,h=s[3]=h+C|0,s[2]=o+B+(h>>>0<C>>>0?1:0)|0,u=s[5]=u+U|0,s[4]=l+E+(u>>>0<U>>>0?1:0)|0,d=s[7]=d+x|0,s[6]=f+k+(d>>>0<x>>>0?1:0)|0,y=s[9]=y+M|0,s[8]=p+V+(y>>>0<M>>>0?1:0)|0,m=s[11]=m+D|0,s[10]=g+S+(m>>>0<D>>>0?1:0)|0,v=s[13]=v+R|0,s[12]=b+P+(v>>>0<R>>>0?1:0)|0,w=s[15]=w+z|0,s[14]=j+O+(w>>>0<z>>>0?1:0)|0}},sjcl.mode.ccm={name:\"ccm\",s:[],listenProgress(t){sjcl.mode.ccm.s.push(t)},unListenProgress(t){-1<(t=sjcl.mode.ccm.s.indexOf(t))&&sjcl.mode.ccm.s.splice(t,1)},H(t){var e=sjcl.mode.ccm.s.slice(),r;for(r=0;r<e.length;r+=1)e[r](t)},encrypt(t,e,i,s,n){var a,c=e.slice(0),o=sjcl.bitArray,h=o.bitLength(i)/8,l=o.bitLength(c)/8;for(n=n||64,s=s||[],7>h&&r(new sjcl.exception.invalid(\"ccm: iv must be at least 7 bytes\")),a=2;4>a&&l>>>8*a;a++);return a<15-h&&(a=15-h),i=o.clamp(i,8*(15-a)),e=sjcl.mode.ccm.o(t,e,i,s,n,a),c=sjcl.mode.ccm.p(t,c,i,e,n,a),o.concat(c.data,c.tag)},decrypt(t,e,i,s,n){n=n||64,s=s||[];var a=sjcl.bitArray,c=a.bitLength(i)/8,o=a.bitLength(e),h=a.clamp(e,o-n),l=a.bitSlice(e,o-n),o=(o-n)/8;for(7>c&&r(new sjcl.exception.invalid(\"ccm: iv must be at least 7 bytes\")),e=2;4>e&&o>>>8*e;e++);return e<15-c&&(e=15-c),i=a.clamp(i,8*(15-e)),h=sjcl.mode.ccm.p(t,h,i,l,n,e),t=sjcl.mode.ccm.o(t,h.data,i,s,n,e),a.equal(h.tag,t)||r(new sjcl.exception.corrupt(\"ccm: tag doesn't match\")),h.data},K(t,e,r,i,s,n){var a=[],c=sjcl.bitArray,o=c.u;if(i=[c.partial(8,(e.length?64:0)|i-2<<2|n-1)],(i=c.concat(i,r))[3]|=s,i=t.encrypt(i),e.length)for(65279>=(r=c.bitLength(e)/8)?a=[c.partial(16,r)]:4294967295>=r&&(a=c.concat([c.partial(16,65534)],[r])),a=c.concat(a,e),e=0;e<a.length;e+=4)i=t.encrypt(o(i,a.slice(e,e+4).concat([0,0,0])));return i},o(t,e,i,s,n,a){var c=sjcl.bitArray,o=c.u;for(((n/=8)%2||4>n||16<n)&&r(new sjcl.exception.invalid(\"ccm: invalid tag length\")),(4294967295<s.length||4294967295<e.length)&&r(new sjcl.exception.bug(\"ccm: can't deal with 4GiB or more data\")),i=sjcl.mode.ccm.K(t,s,i,n,c.bitLength(e)/8,a),s=0;s<e.length;s+=4)i=t.encrypt(o(i,e.slice(s,s+4).concat([0,0,0])));return c.clamp(i,8*n)},p(t,e,r,i,s,n){var a,c=sjcl.bitArray;a=c.u;var o=e.length,h=c.bitLength(e),l=o/50,u=l;if(r=c.concat([c.partial(8,n-1)],r).concat([0,0,0]).slice(0,4),i=c.bitSlice(a(i,t.encrypt(r)),0,s),!o)return{tag:i,data:[]};for(a=0;a<o;a+=4)a>l&&(sjcl.mode.ccm.H(a/o),l+=u),r[3]++,s=t.encrypt(r),e[a]^=s[0],e[a+1]^=s[1],e[a+2]^=s[2],e[a+3]^=s[3];return{tag:i,data:c.clamp(e,h)}}},sjcl.prng=function(t){this.f=[new sjcl.hash.sha256],this.j=[0],this.F=0,this.t={},this.D=0,this.J={},this.L=this.g=this.k=this.S=0,this.b=[0,0,0,0,0,0,0,0],this.h=[0,0,0,0],this.B=s,this.C=t,this.r=v,this.A={progress:{},seeded:{}},this.m=this.R=0,this.v=1,this.w=2,this.O=65536,this.G=[0,48,64,96,128,192,256,384,512,768,1024],this.P=3e4,this.N=80},sjcl.prng.prototype={randomWords(t,e){var i=[],s,n;if((s=this.isReady(e))===this.m&&r(new sjcl.exception.notReady(\"generator isn't seeded\")),s&this.w){s=!(s&this.v),n=[];var a=0,c;for(this.L=n[0]=(new Date).valueOf()+this.P,c=0;16>c;c++)n.push(4294967296*Math.random()|0);for(c=0;c<this.f.length&&(n=n.concat(this.f[c].finalize()),a+=this.j[c],this.j[c]=0,s||!(this.F&1<<c));c++);for(this.F>=1<<this.f.length&&(this.f.push(new sjcl.hash.sha256),this.j.push(0)),this.g-=a,a>this.k&&(this.k=a),this.F++,this.b=sjcl.hash.sha256.hash(this.b.concat(n)),this.B=new sjcl.cipher.aes(this.b),s=0;4>s&&(this.h[s]=this.h[s]+1|0,!this.h[s]);s++);}for(s=0;s<t;s+=4)0==(s+1)%this.O&&ba(this),n=ca(this),i.push(n[0],n[1],n[2],n[3]);return ba(this),i.slice(0,t)},setDefaultParanoia(t,e){0===t&&\"Setting paranoia=0 will ruin your security; use it only for testing\"!==e&&r(\"Setting paranoia=0 will ruin your security; use it only for testing\"),this.C=t},addEntropy(t,e,i){i=i||\"user\";var n,a,c=(new Date).valueOf(),o=this.t[i],h=this.isReady(),l=0;switch((n=this.J[i])===s&&(n=this.J[i]=this.S++),o===s&&(o=this.t[i]=0),this.t[i]=(this.t[i]+1)%this.f.length,typeof t){case\"number\":e===s&&(e=1),this.f[o].update([n,this.D++,1,e,c,1,0|t]);break;case\"object\":if(\"[object Uint32Array]\"===(i=Object.prototype.toString.call(t))){for(a=[],i=0;i<t.length;i++)a.push(t[i]);t=a}else for(\"[object Array]\"!==i&&(l=1),i=0;i<t.length&&!l;i++)\"number\"!=typeof t[i]&&(l=1);if(!l){if(e===s)for(i=e=0;i<t.length;i++)for(a=t[i];0<a;)e++,a>>>=1;this.f[o].update([n,this.D++,2,e,c,t.length].concat(t))}break;case\"string\":e===s&&(e=t.length),this.f[o].update([n,this.D++,3,e,c,t.length]),this.f[o].update(t);break;default:l=1}l&&r(new sjcl.exception.bug(\"random: addEntropy only supports number, array of numbers or string\")),this.j[o]+=e,this.g+=e,h===this.m&&(this.isReady()!==this.m&&da(\"seeded\",Math.max(this.k,this.g)),da(\"progress\",this.getProgress()))},isReady(t){return t=this.G[t!==s?t:this.C],this.k&&this.k>=t?this.j[0]>this.N&&(new Date).valueOf()>this.L?this.w|this.v:this.v:this.g>=t?this.w|this.m:this.m},getProgress(t){return t=this.G[t||this.C],this.k>=t?1:this.g>t?1:this.g/t},startCollectors(){this.r||(this.a={loadTimeCollector:P(this,this.W),mouseCollector:P(this,this.X),keyboardCollector:P(this,this.U),accelerometerCollector:P(this,this.Q),touchCollector:P(this,this.Y)},window.addEventListener?(window.addEventListener(\"load\",this.a.loadTimeCollector,v),window.addEventListener(\"mousemove\",this.a.mouseCollector,v),window.addEventListener(\"keypress\",this.a.keyboardCollector,v),window.addEventListener(\"devicemotion\",this.a.accelerometerCollector,v),window.addEventListener(\"touchmove\",this.a.touchCollector,v)):document.attachEvent?(document.attachEvent(\"onload\",this.a.loadTimeCollector),document.attachEvent(\"onmousemove\",this.a.mouseCollector),document.attachEvent(\"keypress\",this.a.keyboardCollector)):r(new sjcl.exception.bug(\"can't attach event\")),this.r=!0)},stopCollectors(){this.r&&(window.removeEventListener?(window.removeEventListener(\"load\",this.a.loadTimeCollector,v),window.removeEventListener(\"mousemove\",this.a.mouseCollector,v),window.removeEventListener(\"keypress\",this.a.keyboardCollector,v),window.removeEventListener(\"devicemotion\",this.a.accelerometerCollector,v),window.removeEventListener(\"touchmove\",this.a.touchCollector,v)):document.detachEvent&&(document.detachEvent(\"onload\",this.a.loadTimeCollector),document.detachEvent(\"onmousemove\",this.a.mouseCollector),document.detachEvent(\"keypress\",this.a.keyboardCollector)),this.r=v)},addEventListener(t,e){this.A[t][this.R++]=e},removeEventListener(t,e){var r,i,s=this.A[t],n=[];for(i in s)s.hasOwnProperty(i)&&s[i]===e&&n.push(i);for(r=0;r<n.length;r++)delete s[i=n[r]]},U(){Q(1)},X(t){var e,r;try{e=t.x||t.clientX||t.offsetX||0,r=t.y||t.clientY||t.offsetY||0}catch(t){r=e=0}0!=e&&0!=r&&sjcl.random.addEntropy([e,r],2,\"mouse\"),Q(0)},Y(t){t=t.touches[0]||t.changedTouches[0],sjcl.random.addEntropy([t.pageX||t.clientX,t.pageY||t.clientY],1,\"touch\"),Q(0)},W(){Q(2)},Q(t){if(t=t.accelerationIncludingGravity.x||t.accelerationIncludingGravity.y||t.accelerationIncludingGravity.z,window.orientation){var e=window.orientation;\"number\"==typeof e&&sjcl.random.addEntropy(e,1,\"accelerometer\")}t&&sjcl.random.addEntropy(t,2,\"accelerometer\"),Q(0)}},sjcl.random=new sjcl.prng(6);t:try{var V,ea,W,fa;if(fa=\"undefined\"!=typeof module){var ka;if(ka=module.exports){var la;try{la=require(\"crypto\")}catch(t){la=null}ka=(ea=la)&&ea.randomBytes}fa=ka}if(fa)V=ea.randomBytes(128),V=new Uint32Array(new Uint8Array(V).buffer),sjcl.random.addEntropy(V,1024,\"crypto['randomBytes']\");else if(\"undefined\"!=typeof window&&\"undefined\"!=typeof Uint32Array){if(W=new Uint32Array(32),window.crypto&&window.crypto.getRandomValues)window.crypto.getRandomValues(W);else{if(!window.msCrypto||!window.msCrypto.getRandomValues)break t;window.msCrypto.getRandomValues(W)}sjcl.random.addEntropy(W,1024,\"crypto['getRandomValues']\")}}catch(t){\"undefined\"!=typeof window&&window.console&&(console.log(\"There was an error collecting entropy from the browser:\"),console.log(t))}sjcl.arrayBuffer=sjcl.arrayBuffer||{},\"undefined\"==typeof ArrayBuffer&&((a=this).ArrayBuffer=function(){},a.DataView=function(){}),sjcl.arrayBuffer.ccm={mode:\"ccm\",defaults:{tlen:128},compat_encrypt(t,e,r,i,s){var n=sjcl.codec.arrayBuffer.fromBits(e,!0,16);return e=sjcl.bitArray.bitLength(e)/8,i=i||[],t=sjcl.arrayBuffer.ccm.encrypt(t,n,r,i,s||64,e),r=sjcl.codec.arrayBuffer.toBits(t.ciphertext_buffer),r=sjcl.bitArray.clamp(r,8*e),sjcl.bitArray.concat(r,t.tag)},compat_decrypt(t,e,r,i,s){s=s||64,i=i||[];var n=sjcl.bitArray,a=n.bitLength(e),c=n.clamp(e,a-s);return e=n.bitSlice(e,a-s),c=sjcl.codec.arrayBuffer.fromBits(c,!0,16),t=sjcl.arrayBuffer.ccm.decrypt(t,c,r,e,i,s,(a-s)/8),sjcl.bitArray.clamp(sjcl.codec.arrayBuffer.toBits(t),a-s)},encrypt(t,e,r,i,s,n){var a,c=sjcl.bitArray,o=c.bitLength(r)/8;for(i=i||[],s=s||sjcl.arrayBuffer.ccm.defaults.tlen,n=n||e.byteLength,s=Math.ceil(s/8),a=2;4>a&&n>>>8*a;a++);return a<15-o&&(a=15-o),r=c.clamp(r,8*(15-a)),i=sjcl.arrayBuffer.ccm.o(t,e,r,i,s,n,a),{ciphertext_buffer:e,tag:i=sjcl.arrayBuffer.ccm.p(t,e,r,i,s,a)}},decrypt(t,e,i,s,n,a,c){var o,h=sjcl.bitArray,l=h.bitLength(i)/8;for(n=n||[],a=a||sjcl.arrayBuffer.ccm.defaults.tlen,c=c||e.byteLength,a=Math.ceil(a/8),o=2;4>o&&c>>>8*o;o++);return o<15-l&&(o=15-l),i=h.clamp(i,8*(15-o)),s=sjcl.arrayBuffer.ccm.p(t,e,i,s,a,o),t=sjcl.arrayBuffer.ccm.o(t,e,i,n,a,c,o),sjcl.bitArray.equal(s,t)||r(new sjcl.exception.corrupt(\"ccm: tag doesn't match\")),e},o(t,e,r,i,s,n,a){if(r=sjcl.mode.ccm.K(t,i,r,s,n,a),0!==e.byteLength){for(i=new DataView(e);n<e.byteLength;n++)i.setUint8(n,0);for(n=0;n<i.byteLength;n+=16)r[0]^=i.getUint32(n),r[1]^=i.getUint32(n+4),r[2]^=i.getUint32(n+8),r[3]^=i.getUint32(n+12),r=t.encrypt(r)}return sjcl.bitArray.clamp(r,8*s)},p(t,e,r,i,s,n){var a,c,o,h,l;c=(a=sjcl.bitArray).u;var u=e.byteLength/50,f=u;if(new DataView(new ArrayBuffer(16)),r=a.concat([a.partial(8,n-1)],r).concat([0,0,0]).slice(0,4),i=a.bitSlice(c(i,t.encrypt(r)),0,8*s),r[3]++,0===r[3]&&r[2]++,0!==e.byteLength)for(s=new DataView(e),l=0;l<s.byteLength;l+=16)l>u&&(sjcl.mode.ccm.H(l/e.byteLength),u+=f),h=t.encrypt(r),a=s.getUint32(l),c=s.getUint32(l+4),n=s.getUint32(l+8),o=s.getUint32(l+12),s.setUint32(l,a^h[0]),s.setUint32(l+4,c^h[1]),s.setUint32(l+8,n^h[2]),s.setUint32(l+12,o^h[3]),r[3]++,0===r[3]&&r[2]++;return i}},\"undefined\"==typeof ArrayBuffer&&function(t){t.ArrayBuffer=function(){},t.DataView=function(){}}(this),sjcl.codec.arrayBuffer={fromBits(t,e,i){var n;if(e=e==s||e,i=i||8,0===t.length)return new ArrayBuffer(0);for(n=sjcl.bitArray.bitLength(t)/8,0!=sjcl.bitArray.bitLength(t)%8&&r(new sjcl.exception.invalid(\"Invalid bit size, must be divisble by 8 to fit in an arraybuffer correctly\")),e&&0!=n%i&&(n+=i-n%i),i=new DataView(new ArrayBuffer(4*t.length)),e=0;e<t.length;e++)i.setUint32(4*e,t[e]<<32);if((t=new DataView(new ArrayBuffer(n))).byteLength===i.byteLength)return i.buffer;for(n=i.byteLength<t.byteLength?i.byteLength:t.byteLength,e=0;e<n;e++)t.setUint8(e,i.getUint8(e));return t.buffer},toBits(t){var e=[],r,i,s;if(0===t.byteLength)return[];for(r=(i=new DataView(t)).byteLength-i.byteLength%4,t=0;t<r;t+=4)e.push(i.getUint32(t));if(0!=i.byteLength%4){s=new DataView(new ArrayBuffer(4)),t=0;for(var n=i.byteLength%4;t<n;t++)s.setUint8(t+4-n,i.getUint8(r+t));e.push(sjcl.bitArray.partial(i.byteLength%4*8,s.getUint32(0)))}return e},Z(t){function e(t){return 4<=(t+=\"\").length?t:Array(4-t.length+1).join(\"0\")+t}t=new DataView(t);for(var r=\"\",i=0;i<t.byteLength;i+=2)0==i%16&&(r+=\"\\n\"+i.toString(16)+\"\\t\"),r+=e(t.getUint16(i).toString(16))+\" \";typeof console===s&&(console=console||{log(){}}),console.log(r.toUpperCase())}};\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIjAiXSwibmFtZXMiOlsiciIsImEiLCJzIiwidiIsIkgiLCJzamNsIiwiY2lwaGVyIiwiaGFzaCIsImtleWV4Y2hhbmdlIiwibW9kZSIsIm1pc2MiLCJjb2RlYyIsImV4Y2VwdGlvbiIsIltvYmplY3QgT2JqZWN0XSIsInRoaXMiLCJ0b1N0cmluZyIsIm1lc3NhZ2UiLCJhYSIsImIiLCJjIiwibGVuZ3RoIiwiaW52YWxpZCIsImQiLCJlIiwiZyIsImYiLCJoIiwiayIsIm4iLCJsIiwibSIsInAiLCJ3IiwiRCIsIkIiLCJFIiwiQyIsImRhIiwicmFuZG9tIiwiQSIsImhhc093blByb3BlcnR5IiwicHVzaCIsIlEiLCJ3aW5kb3ciLCJwZXJmb3JtYW5jZSIsIm5vdyIsImFkZEVudHJvcHkiLCJEYXRlIiwidmFsdWVPZiIsImJhIiwiY2EiLCJjb25jYXQiLCJhZXMiLCJlbmNyeXB0IiwiUCIsImFwcGx5IiwiYXJndW1lbnRzIiwibW9kdWxlIiwiZXhwb3J0cyIsImRlZmluZSIsInEiLCJzbGljZSIsInByb3RvdHlwZSIsImJpdEFycmF5IiwiTSIsImNsYW1wIiwiTWF0aCIsImZsb29yIiwiZ2V0UGFydGlhbCIsImNlaWwiLCJwYXJ0aWFsIiwicm91bmQiLCJiaXRMZW5ndGgiLCJwb3AiLCJ1dGY4U3RyaW5nIiwiU3RyaW5nIiwiZnJvbUNoYXJDb2RlIiwiZGVjb2RlVVJJQ29tcG9uZW50IiwiZXNjYXBlIiwidW5lc2NhcGUiLCJlbmNvZGVVUklDb21wb25lbnQiLCJjaGFyQ29kZUF0IiwiYmFzZTY0IiwiSSIsInN1YnN0ciIsImNoYXJBdCIsInJlcGxhY2UiLCJpbmRleE9mIiwiYmFzZTY0dXJsIiwiZnJvbUJpdHMiLCJ0b0JpdHMiLCJieXRlcyIsInNoYTI1NiIsInJlc2V0IiwidXBkYXRlIiwiZmluYWxpemUiLCJibG9ja1NpemUiLCJpIiwic3BsaWNlIiwicG93Iiwic2hhNTEyIiwiVCIsIlYiLCJnYSIsIlIiLCJoYSIsIlMiLCJ4IiwidCIsIkYiLCJKIiwiRyIsIlgiLCJLIiwieSIsInUiLCJMIiwiVSIsIlkiLCJOIiwieiIsIloiLCIkIiwiTyIsImlhIiwibWEiLCJuYSIsImphIiwiY2NtIiwibmFtZSIsIm8iLCJkYXRhIiwidGFnIiwiYml0U2xpY2UiLCJlcXVhbCIsImNvcnJ1cHQiLCJidWciLCJwcm5nIiwiaiIsInByb2dyZXNzIiwic2VlZGVkIiwiaXNSZWFkeSIsIm5vdFJlYWR5IiwiT2JqZWN0IiwiY2FsbCIsIm1heCIsImdldFByb2dyZXNzIiwibG9hZFRpbWVDb2xsZWN0b3IiLCJXIiwibW91c2VDb2xsZWN0b3IiLCJrZXlib2FyZENvbGxlY3RvciIsImFjY2VsZXJvbWV0ZXJDb2xsZWN0b3IiLCJ0b3VjaENvbGxlY3RvciIsImFkZEV2ZW50TGlzdGVuZXIiLCJkb2N1bWVudCIsImF0dGFjaEV2ZW50IiwicmVtb3ZlRXZlbnRMaXN0ZW5lciIsImRldGFjaEV2ZW50IiwiY2xpZW50WCIsIm9mZnNldFgiLCJjbGllbnRZIiwib2Zmc2V0WSIsInRvdWNoZXMiLCJjaGFuZ2VkVG91Y2hlcyIsInBhZ2VYIiwicGFnZVkiLCJhY2NlbGVyYXRpb25JbmNsdWRpbmdHcmF2aXR5Iiwib3JpZW50YXRpb24iLCJlYSIsImZhIiwia2EiLCJsYSIsInJlcXVpcmUiLCJvYSIsInJhbmRvbUJ5dGVzIiwiVWludDMyQXJyYXkiLCJVaW50OEFycmF5IiwiYnVmZmVyIiwiY3J5cHRvIiwiZ2V0UmFuZG9tVmFsdWVzIiwibXNDcnlwdG8iLCJwYSIsImNvbnNvbGUiLCJsb2ciLCJhcnJheUJ1ZmZlciIsIkFycmF5QnVmZmVyIiwiRGF0YVZpZXciLCJkZWZhdWx0cyIsInRsZW4iLCJjaXBoZXJ0ZXh0X2J1ZmZlciIsImRlY3J5cHQiLCJieXRlTGVuZ3RoIiwic2V0VWludDgiLCJnZXRVaW50MzIiLCJzZXRVaW50MzIiLCJnZXRVaW50OCIsIkFycmF5Iiwiam9pbiIsImdldFVpbnQxNiIsInRvVXBwZXJDYXNlIl0sIm1hcHBpbmdzIjoiQUE2REEsYUFFQSxTQUFTQSxFQUFF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"},
            'smalltalk.js': {"requiresElectron":false,"requiresBrowser":true,"code":"\"use strict\";$(\"head\").append(\"<style>.smalltalk{display:flex;align-items:center;flex-direction:column;justify-content:center;transition:200ms opacity;bottom:0;left:0;overflow:auto;padding:20px;position:fixed;right:0;top:0;z-index:100}.smalltalk + .smalltalk{transition:ease 1s;display:none}.smalltalk .page{border-radius:3px;background:white;box-shadow:0 4px 23px 5px rgba(0, 0, 0, .2), 0 2px 6px rgba(0, 0, 0, .15);color:#333;min-width:400px;padding:0;position:relative;z-index:0}@media only screen and (max-width: 500px){.smalltalk .page{min-width:0}}.smalltalk .page > .close-button{background: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAAUklEQVR4XqXPYQrAIAhAYW/gXd8NJxTopVqsGEhtf+L9/ERU2k/HSMFQpKcYJeNFI9Be0LCMij8cYyjj5EHIivGBkwLfrbX3IF8PqumVmnDpEG+eDsKibPG2JwAAAABJRU5ErkJggg==') no-repeat center;height:14px;position:absolute;right:7px;top:7px;width:14px;z-index:1}.smalltalk .page > .close-button:hover{background-image:url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAAnUlEQVR4XoWQQQ6CQAxFewjkJkMCyXgJPMk7AiYczyBeZEAX6AKctGIaN+bt+trk9wtGQc/IkhnoKGxqqiWxOSZalapWFZ6VrIUDExsN0a5JRBq9LoVOR0eEQMoEhKizXhhsn0p1sCWVo7CwOf1RytPL8CPvwuBUoHL6ugeK30CVD1TqK7V/hdpe+VNChhOzV8xWny/+xosHF8578W/Hmc1OOC3wmwAAAABJRU5ErkJggg==')}.smalltalk .page header{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:500px;user-select:none;color:#333;font-size:120%;font-weight:bold;margin:0;padding:14px 17px;text-shadow:white 0 1px 2px}.smalltalk .page .content-area{overflow:hidden;text-overflow:ellipsis;padding:6px 17px;position:relative}.smalltalk .page .action-area{padding:14px 17px}button{font-family:Ubuntu, Arial, sans-serif}.smalltalk .smalltalk,.smalltalk button{min-height:2em;min-width:4em}.smalltalk button{appearance:none;user-select:none;background-image:linear-gradient(#ededed, #ededed 38%, #dedede);border:1px solid rgba(0, 0, 0, 0.25);border-radius:2px;box-shadow:0 1px 0 rgba(0, 0, 0, 0.08), inset 0 1px 2px rgba(255, 255, 255, 0.75);color:#444;font:inherit;margin:0 1px 0 0;text-shadow:0 1px 0 rgb(240, 240, 240)}.smalltalk button::-moz-focus-inner{border:0}.smalltalk button:enabled:active{background-image:linear-gradient(#e7e7e7, #e7e7e7 38%, #d7d7d7);box-shadow:none;text-shadow:none}.smalltalk .page .button-strip{display:flex;flex-direction:row;justify-content:flex-end}.smalltalk .page .button-strip > button{margin-left:10px}.smalltalk input{width:100%;border:1px solid #bfbfbf;border-radius:2px;box-sizing:border-box;color:#444;font:inherit;margin:0;min-height:2em;padding:3px;outline:none}.smalltalk button:enabled:focus,.smalltalk input:enabled:focus{transition:border-color 200ms;border-color:rgb(77, 144, 254);outline:none}\");const BUTTON_OK=[\"OK\"],BUTTON_OK_CANCEL=[\"OK\",\"Cancel\"],__smalltalk_remove=__smalltalk_bind(__smalltalk_removeEl,\".smalltalk\"),__smalltalk_store=t=>{const a={value:t};return function(t){return arguments.length?(a.value=t,t):a.value}};function _alert(t,a){return __smalltalk_showDialog(t,a,\"\",BUTTON_OK,{cancel:!1})}function _prompt(t,a,e=\"\",l){const n=__smalltalk_getType(l),o=String(e).replace(/\"/g,\"&quot;\"),s=`<input type=\"${n}\" value=\"${o}\" data-name=\"js-input\">`;return __smalltalk_showDialog(t,a,s,BUTTON_OK_CANCEL,l)}function _confirm(t,a,e){return __smalltalk_showDialog(t,a,\"\",BUTTON_OK_CANCEL,e)}function __smalltalk_getType(t={}){const{type:a}=t;return\"password\"===a?\"password\":\"text\"}function __smalltalk_getTemplate(t,a,e,l){const n=a.replace(/\\n/g,\"<br>\");return`<div class=\"page\">\\n        <div data-name=\"js-close\" class=\"close-button\"></div>\\n        <header>${t}</header>\\n        <div class=\"content-area\">${n}${e}</div>\\n        <div class=\"action-area\">\\n            <div class=\"button-strip\"> ${l.map((t,a)=>`<button tabindex=${a} data-name=\"js-${t.toLowerCase()}\">${t}</button>`).join(\"\")}\\n            </div>\\n        </div>\\n    </div>`}function __smalltalk_showDialog(t,a,e,l,n){const o=__smalltalk_store(),s=__smalltalk_store(),i=document.createElement(\"div\"),r=[\"cancel\",\"close\",\"ok\"],_=new Promise((t,a)=>{const e=n&&!n.cancel,l=()=>{};o(t),s(e?l:a)});return i.innerHTML=__smalltalk_getTemplate(t,a,e,l),i.className=\"smalltalk\",document.body.appendChild(i),__smalltalk_find(i,[\"ok\",\"input\"]).forEach(t=>t.focus()),__smalltalk_find(i,[\"input\"]).forEach(t=>{t.setSelectionRange(0,e.length)}),__smalltalk_addListenerAll(\"click\",i,r,t=>__smalltalk_closeDialog(t.target,i,o(),s())),[\"click\",\"contextmenu\"].forEach(t=>i.addEventListener(t,()=>__smalltalk_find(i,[\"ok\",\"input\"]).forEach(t=>t.focus()))),i.addEventListener(\"keydown\",currify(__smalltalk_keyDownEvent)(i,o(),s())),_}function __smalltalk_keyDownEvent(t,a,e,l){const n={ENTER:13,ESC:27,TAB:9,LEFT:37,UP:38,RIGHT:39,DOWN:40},o=l.keyCode,s=l.target,i=[\"ok\",\"cancel\",\"input\"],r=__smalltalk_find(t,i).map(__smalltalk_getDataName);switch(o){case n.ENTER:__smalltalk_closeDialog(s,t,a,e),l.preventDefault();break;case n.ESC:__smalltalk_remove(),e();break;case n.TAB:l.shiftKey&&__smalltalk_tab(t,r),__smalltalk_tab(t,r),l.preventDefault();break;default:[\"left\",\"right\",\"up\",\"down\"].filter(t=>o===n[t.toUpperCase()]).forEach(()=>{__smalltalk_changeButtonFocus(t,r)})}l.stopPropagation()}function __smalltalk_getDataName(t){return t.getAttribute(\"data-name\").replace(\"js-\",\"\")}function __smalltalk_changeButtonFocus(t,a){const e=document.activeElement,l=__smalltalk_getDataName(e),n=/ok|cancel/.test(l),o=a.length-1,s=t=>\"cancel\"===t?\"ok\":\"cancel\";if(\"input\"===l||!o||!n)return;const i=s(l);__smalltalk_find(t,[i]).forEach(t=>{t.focus()})}const __smalltalk_getIndex=(t,a)=>a===t?0:a+1;function __smalltalk_tab(t,a){const e=document.activeElement,l=__smalltalk_getDataName(e),n=a.length-1,o=a.indexOf(l),s=__smalltalk_getIndex(n,o),i=a[s];__smalltalk_find(t,[i]).forEach(t=>t.focus())}function __smalltalk_closeDialog(t,a,e,l){const n=t.getAttribute(\"data-name\").replace(\"js-\",\"\");if(/close|cancel/.test(n))return l(),void __smalltalk_remove();const o=__smalltalk_find(a,[\"input\"]).reduce((t,a)=>a.value,null);e(o),__smalltalk_remove()}function __smalltalk_find(t,a){const e=t=>t,l=a.map(a=>t.querySelector(`[data-name=\"js-${a}\"]`)).filter(e);return l}function __smalltalk_addListenerAll(t,a,e,l){__smalltalk_find(a,e).forEach(a=>a.addEventListener(t,l))}function __smalltalk_removeEl(t){const a=document.querySelector(t);a.parentElement.removeChild(a)}function __smalltalk_bind(t,...a){return()=>t(...a)}\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIjAiXSwibmFtZXMiOlsiJCIsImFwcGVuZCIsIkJVVFRPTl9PSyIsIkJVVFRPTl9PS19DQU5DRUwiLCJfX3NtYWxsdGFsa19yZW1vdmUiLCJfX3NtYWxsdGFsa19iaW5kIiwiX19zbWFsbHRhbGtfcmVtb3ZlRWwiLCJfX3NtYWxsdGFsa19zdG9yZSIsInZhbHVlIiwiZGF0YSIsImFyZ3VtZW50cyIsImxlbmd0aCIsIl9hbGVydCIsInRpdGxlIiwibXNnIiwiX19zbWFsbHRhbGtfc2hvd0RpYWxvZyIsImNhbmNlbCIsIl9wcm9tcHQiLCJvcHRpb25zIiwidHlwZSIsIl9fc21hbGx0YWxrX2dldFR5cGUiLCJ2YWwiLCJTdHJpbmciLCJyZXBsYWNlIiwidmFsdWVTdHIiLCJfY29uZmlybSIsIl9fc21hbGx0YWxrX2dldFRlbXBsYXRlIiwiYnV0dG9ucyIsImVuY29kZWRNc2ciLCJtYXAiLCJuYW1lIiwiaSIsInRvTG93ZXJDYXNlIiwiam9pbiIsIm9rIiwiZGlhbG9nIiwiZG9jdW1lbnQiLCJjcmVhdGVFbGVtZW50IiwiY2xvc2VCdXR0b25zIiwicHJvbWlzZSIsIlByb21pc2UiLCJyZXNvbHZlIiwicmVqZWN0Iiwibm9DYW5jZWwiLCJlbXB0eSIsImlubmVySFRNTCIsImNsYXNzTmFtZSIsImJvZHkiLCJhcHBlbmRDaGlsZCIsIl9fc21hbGx0YWxrX2ZpbmQiLCJmb3JFYWNoIiwiZWwiLCJmb2N1cyIsInNldFNlbGVjdGlvblJhbmdlIiwiX19zbWFsbHRhbGtfYWRkTGlzdGVuZXJBbGwiLCJldmVudCIsIl9fc21hbGx0YWxrX2Nsb3NlRGlhbG9nIiwidGFyZ2V0IiwiYWRkRXZlbnRMaXN0ZW5lciIsImN1cnJpZnkiLCJfX3NtYWxsdGFsa19rZXlEb3duRXZlbnQiLCJLRVkiLCJFTlRFUiIsIkVTQyIsIlRBQiIsIkxFRlQiLCJVUCIsIlJJR0hUIiwiRE9XTiIsImtleUNvZGUiLCJuYW1lc0FsbCIsIm5hbWVzIiwiX19zbWFsbHRhbGtfZ2V0RGF0YU5hbWUiLCJwcmV2ZW50RGVmYXVsdCIsInNoaWZ0S2V5IiwiX19zbWFsbHRhbGtfdGFiIiwiZmlsdGVyIiwidG9VcHBlckNhc2UiLCJfX3NtYWxsdGFsa19jaGFuZ2VCdXR0b25Gb2N1cyIsInN0b3BQcm9wYWdhdGlvbiIsImdldEF0dHJpYnV0ZSIsImFjdGl2ZSIsImFjdGl2ZUVsZW1lbnQiLCJhY3RpdmVOYW1lIiwiaXNCdXR0b24iLCJ0ZXN0IiwiY291bnQiLCJnZXROYW1lIiwiX19zbWFsbHRhbGtfZ2V0SW5kZXgiLCJpbmRleCIsImFjdGl2ZUluZGV4IiwiaW5kZXhPZiIsInJlZHVjZSIsImVsZW1lbnQiLCJub3RFbXB0eSIsImEiLCJlbGVtZW50cyIsInF1ZXJ5U2VsZWN0b3IiLCJwYXJlbnQiLCJmbiIsInBhcmVudEVsZW1lbnQiLCJyZW1vdmVDaGlsZCIsImFyZ3MiXSwibWFwcGluZ3MiOiJBQXdCQSxhQUVBQSxFQUFFLFFBQVFDLE9BQU8sNm5GQUVqQixNQUFNQyxXQUFhLE1BQ2JDLGtCQUFvQixLQUFNLFVBRTFCQyxtQkFBcUJDLGlCQUFrQkMscUJBQXNCLGNBRzdEQyxrQkFBc0JDLElBQ3hCLE1BQU1DLEdBQ0ZELE1BQUFBLEdBR0osT0FBTyxTQUFXQSxHQUNkLE9BQU1FLFVBQVVDLFFBR2hCRixFQUFLRCxNQUFRQSxFQUVOQSxHQUpJQyxFQUFLRCxRQVF4QixTQUFTSSxPQUFRQyxFQUFPQyxHQUNwQixPQUFPQyx1QkFBd0JGLEVBQU9DLEVBQUssR0FBSVosV0FBYWMsUUFBUSxJQUd4RSxTQUFTQyxRQUFTSixFQUFPQyxFQUFLTixFQUFRLEdBQUlVLEdBQ3RDLE1BQU1DLEVBQU9DLG9CQUFxQkYsR0FFNUJHLEVBQU1DLE9BQVFkLEdBQ2ZlLFFBQVMsS0FBTSxVQUVkQyxrQkFBNEJMLGFBQWtCRSwyQkFFcEQsT0FBT04sdUJBQXdCRixFQUFPQyxFQUFLVSxFQUFVckIsaUJBQWtCZSxHQUczRSxTQUFTTyxTQUFVWixFQUFPQyxFQUFLSSxHQUMzQixPQUFPSCx1QkFBd0JGLEVBQU9DLEVBQUssR0FBSVgs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"}
        };
    }

    /* ============================================================== */

    /* ===================== STANDARD CALLBACKS ===================== */

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
            HighlightJS: WebpackModules
                .findByUniqueProperties( [ 'initHighlighting', 'highlightBlock', 'highlightAuto' ] ),
        };

        /* Hook switch events as the main event processor. */
        if ( !this.hookMessageCallbacks() ) {
            /* The toolbar fails to properly load on switches to the friends list. Create an interval to do this. */
            this.toolbarReloadInterval = setInterval( () => {
                self.loadToolbar();
                self.attachHandler();
            }, 5000 );
        }
        else {
            /* Add the toolbar. */
            this.loadToolbar();

            /* Attach the message handler. */
            this.attachHandler();
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
                        discordCrypt.log( e.messageId + ': ' + e.toString(), 'error' );
                    }

                    /* Delete the index. */
                    self.configFile.timedMessages.splice( i, 1 );

                    /* Update the configuration to the disk. */
                    self.saveConfig();
                }
            } );

        }, 5000 );

        /* Decode all messages immediately. */
        this.decodeMessages();
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
        $( '#dc-lock-btn' ).remove();
        $( '#dc-passwd-btn' ).remove();
        $( '#dc-exchange-btn' ).remove();
        $( '#dc-settings-btn' ).remove();
        $( '#dc-toolbar-line' ).remove();

        /* Clear the configuration file. */
        this.configFile = null;
    }

    /**
     * @public
     * @desc Triggered when the script has to load resources. This is called once upon Discord startup.
     */
    load() {
        /* Inject application CSS. */
        discordCrypt.injectCSS( 'dc-css', this.appCss );

        /* Load necessary libraries. */
        discordCrypt.loadLibraries( this.libraries );
    }

    /**
     * @public
     * @desc Triggered when the script needs to unload its resources. This is called during Discord shutdown.
     */
    unload() {
        /* Clear the injected CSS. */
        discordCrypt.clearCSS( 'dc-css' );
    }

    /* =================== END STANDARD CALLBACKS =================== */

    /* =================== CONFIGURATION DATA CBS =================== */

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
            useEmbeds: true,
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
     * @param {Object} btn The jQuery button to set the update text for.
     */
    saveSettings( btn ) {
        /* Save the configuration file. */
        this.saveConfig();

        /* Tell the user that their settings were applied. */
        btn.innerHTML = "Saved & Applied!";

        /* Reset the original text after a second. */
        setTimeout( ( function () {
            btn.innerHTML = "Save & Apply";
        } ), 1000 );

        /* Force decode messages. */
        this.decodeMessages( true );
    }

    /**
     * @private
     * @desc Resets the default configuration data used and updates a given button's text.
     * @param {Object} btn The jQuery button to set the update text for.
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

        /* Tell the user that their settings were reset. */
        btn.innerHTML = "Restored Default Settings!";

        /* Reset the original text after a second. */
        setTimeout( ( function () {
            btn.innerHTML = "Reset Settings";
        } ), 1000 );

        /* Force decode messages. */
        this.decodeMessages( true );
    }

    /**
     * @private
     * @desc Update the current password field and save the config file.
     */
    updatePasswords() {
        /* Don't save if the password overlay is not open. */
        if ( $( '#dc-overlay-password' )[ 0 ].style.display !== 'block' )
            return;

        let prim = $( "#dc-password-primary" );
        let sec = $( "#dc-password-secondary" );

        /* Check if a primary password has actually been entered. */
        if ( !( prim[ 0 ].value !== '' && prim[ 0 ].value.length > 1 ) )
            delete this.configFile.passList[ discordCrypt.getChannelId() ];
        else {
            /* Update the password field for this id. */
            this.configFile.passList[ discordCrypt.getChannelId() ] =
                discordCrypt.createPassword( prim[ 0 ].value, '' );

            /* Only check for a secondary password if the primary password has been entered. */
            if ( sec[ 0 ].value !== '' && sec[ 0 ].value.length > 1 )
                this.configFile.passList[ discordCrypt.getChannelId() ].secondary = sec[ 0 ].value;

            /* Update the password toolbar. */
            prim[ 0 ].value = "";
            sec[ 0 ].value = "";
        }

        /* Save the configuration file and decode any messages. */
        this.saveConfig();

        /* Decode any messages with the new password(s). */
        this.decodeMessages( true );
    }

    /* ================= END CONFIGURATION CBS ================= */

    /* =================== PROJECT UTILITIES =================== */

    /**
     * @public
     * @desc Removes the extension from a file name.
     * @param {string} file_name The name of the script file.
     * @return {string} Returns the sanitized file name.
     */
    static sanitizeScriptNameToVariable( file_name ) {
        return file_name.replace( '.js', '' )
    }

    /**
     * @public
     * @desc Loads all compiled libraries as needed.
     * @param {LibraryDefinition} libraries A list of all libraries to load.
     */
    static loadLibraries( libraries ) {
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

            /* Determine how to run this. */
            if ( libInfo.requiresBrowser || libInfo.requiresElectron ) {
                /* Run in the current context as it operates on currently defined objects. */
                vm.runInThisContext( libInfo.code, {
                    filename: name,
                    displayErrors: false
                } );
            }
            else {
                /* Run in a new sandbox and store the result in a global object. */
                global[ discordCrypt.sanitizeScriptNameToVariable( name ) ] =
                    vm.runInNewContext(
                        libInfo.code,
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
     * @public
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

                    return;
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
                    return;
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
                    version_number = data.match( /('[0-9]+\.[0-9]+\.[0-9]+')/gi ).toString().replace( /('*')/g, '' );
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
                }
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
     * @public
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
     * @public
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
                module[ '_actionHandlers' ] !== undefined,
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

        return { find, findByUniqueProperties, findByDisplayName, findByDispatchToken, findByDispatchNames };
    }

    /**
     * @private
     * @experimental
     * @desc Dumps all function callback handlers with their names, IDs and function prototypes. [ Debug Function ]
     * @returns {Array} Returns an array of all IDs and identifier callbacks.
     */
    static dumpWebpackModuleCallbacks() {
        /* Resolve the finder function. */
        let finder = discordCrypt.getWebpackModuleSearcher().findByDispatchToken;

        /* Create the dumping array. */
        let dump = [];

        /* Iterate over let's say 500 possible modules ? In reality, there's < 100. */
        for ( let i = 0; i < 500; i++ ) {
            /* Locate the module. */
            let module = finder( i );

            /* Skip if it's invalid. */
            if ( !module )
                continue;

            /* Create an entry in the array. */
            dump[ i ] = {};

            /* Loop over every property name in the action handler. */
            for ( let prop in module._actionHandlers ) {

                /* Quick sanity check. */
                if ( !module._actionHandlers.hasOwnProperty( prop ) )
                    continue;

                /* Assign the module property name and it's basic prototype. */
                dump[ i ][ prop ] = module._actionHandlers[ prop ].prototype.constructor.toString().split( '{' )[ 0 ];
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

        if ( cached_modules ) {
            return {
                ChannelProps:
                    discordCrypt.getChannelId() === '@me' ?
                        null :
                        discordCrypt.__getElementReactOwner( $( 'form' )[ 0 ] ).props.channel,
                MessageParser: cached_modules.MessageParser,
                MessageController: cached_modules.MessageController,
                MessageActionTypes: cached_modules.MessageActionTypes,
                MessageDispatcher: cached_modules.MessageDispatcher,
                MessageQueue: cached_modules.MessageQueue,
                HighlightJS: cached_modules.HighlightJS,
            };
        }

        return null;
    }

    /**
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
     * @param {Array<TimedMessage>} timed_messages Array containing timed messages to add this sent message to.
     * @param {int} expire_time_minutes The amount of minutes till this message is to be deleted.
     */
    static dispatchMessage(
        as_embed,
        main_message,
        message_header,
        message_footer,
        embedded_color = 0x551A8B,
        message_content = '',
        channel_id = undefined,
        cached_modules = undefined,
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
     * log( 'This is printed green.', 'success' );
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
    static clearCSS( id = undefined ) {
        /* Make sure the ID is a valid string. */
        if ( !id || typeof id !== 'string' || !id.length )
            return;

        /* Remove the element. */
        $( `#${id.replace( /^[^a-z]+|[^\w-]+/gi, "" )}` ).remove();
    }

    /* ================= END PROJECT UTILITIES ================= */

    /* ================= BEGIN MAIN CALLBACKS ================== */

    /**
     * @desc Hooks a dispatcher from Discord's internals.
     * @author samogot & Leonardo Gates
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
        $( document.body ).prepend( this.masterPasswordHtml );

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
                    $( '#dc-overlay' )[ 0 ].style.display = 'block';
                    $( '#dc-update-overlay' )[ 0 ].style.display = 'block';

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
     * @desc Sets the active tab index in the exchange key menu.
     * @param {int} index The index ( 0-2 ) of the page to activate.
     * @example
     * setActiveTab( 1 );
     */
    static setActiveTab( index ) {
        let tab_names = [ 'dc-about-tab', 'dc-keygen-tab', 'dc-handshake-tab' ];
        let tabs = $( '.dc-tab-link' );

        /* Hide all tabs. */
        for ( let i = 0; i < tab_names.length; i++ )
            $( `#${tab_names[ i ]}` )[ 0 ].style.display = 'none';

        /* Deactivate all links. */
        for ( let i = 0; i < tabs.length; i++ )
            tabs[ i ].className = tabs[ i ].className.split( ' active' ).join( '' );

        switch ( index ) {
            case 0:
                $( '#dc-tab-info-btn' )[ 0 ].className += ' active';
                $( '#dc-about-tab' )[ 0 ].style.display = 'block';
                break;
            case 1:
                $( '#dc-tab-keygen-btn' )[ 0 ].className += ' active';
                $( '#dc-keygen-tab' )[ 0 ].style.display = 'block';
                break;
            case 2:
                $( '#dc-tab-handshake-btn' )[ 0 ].className += ' active';
                $( '#dc-handshake-tab' )[ 0 ].style.display = 'block';
                break;
            default:
                break;
        }
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
        $( this.searchUiClass ).parent().parent().parent().prepend( this.toolbarHtml );

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
                dc_lock_btn[ 0 ].innerHTML = Buffer.from( this.lockIcon, 'base64' ).toString( 'utf8' );
            }
            else {
                dc_lock_btn.attr( 'title', 'Enable Message Encryption' );
                dc_lock_btn[ 0 ].innerHTML = Buffer.from( this.unlockIcon, 'base64' ).toString( 'utf8' );
            }

            /* Set the button class. */
            dc_svg.attr( 'class', 'dc-svg' );
        }

        /* Inject the settings. */
        $( document.body ).prepend( this.settingsMenuHtml );

        /* Also by default, set the about tab to be shown. */
        discordCrypt.setActiveTab( 0 );

        /* Update all settings from the settings panel. */
        $( '#dc-secondary-cipher' )[ 0 ].value = discordCrypt.cipherIndexToString( this.configFile.encryptMode, true );
        $( '#dc-primary-cipher' )[ 0 ].value = discordCrypt.cipherIndexToString( this.configFile.encryptMode, false );
        $( '#dc-settings-cipher-mode' )[ 0 ].value = this.configFile.encryptBlockMode.toLowerCase();
        $( '#dc-settings-padding-mode' )[ 0 ].value = this.configFile.paddingMode.toLowerCase();
        $( '#dc-settings-encrypt-trigger' )[ 0 ].value = this.configFile.encodeMessageTrigger;
        $( '#dc-settings-timed-expire' )[ 0 ].value = this.configFile.timedMessageExpires;
        $( '#dc-settings-default-pwd' )[ 0 ].value = this.configFile.defaultPassword;
        $( '#dc-settings-scan-delay' )[ 0 ].value = this.configFile.encryptScanDelay;
        $( '#dc-embed-enabled' )[ 0 ].checked = this.configFile.useEmbeds;

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
            if ( !!$( self.autoCompleteClass )[ 0 ] )
                return;

            /* Send the encrypted message. */
            if ( self.sendEncryptedMessage( $( this ).val() ) != 0 )
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
                dc_keygen_method[ 0 ].value !== metadata[ 'algorithm' ] ||
                parseInt( dc_keygen_algorithm[ 0 ].value ) !== metadata[ 'bit_length' ]
            ) {
                /* Switch. */
                dc_keygen_method[ 0 ].value = metadata[ 'algorithm' ];

                /* Fire the change event so the second list updates. */
                dc_keygen_method.change();

                /* Update the key size. */
                dc_keygen_algorithm[ 0 ].value = metadata[ 'bit_length' ];

                /* Generate a new key pair. */
                $( '#dc-keygen-gen-btn' ).click();

                /* Send the public key. */
                $( '#dc-keygen-send-pub-btn' ).click();
            }
            /* If we don't have a key yet, generate and send one. */
            else if ( $( '#dc-pub-key-ta' )[ 0 ].value === '' ) {
                /* Generate a new key pair. */
                $( '#dc-keygen-gen-btn' ).click();

                /* Send the public key. */
                $( '#dc-keygen-send-pub-btn' ).click();
            }

            /* Open the handshake menu. */
            $( '#dc-tab-handshake-btn' ).click();

            /* Apply the key to the field. */
            $( '#dc-handshake-ppk' )[ 0 ].value = obj.text();

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
            dataMsg = discordCrypt.postProcessMessage( dataMsg, this.configFile.up1Host );

            /* Handle embeds and inline blocks differently. */
            if ( as_embed ) {
                /* Set the new HTML. */
                message[ 0 ].innerHTML = dataMsg.html;
            }
            else {
                /* For inline code blocks, we set the HTML to the parent element. */
                let tmp = message.parent()[ 0 ];
                tmp.innerHTML = dataMsg.html;

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
                        $( elements[ i ] ).children()[ 0 ].className = 'hljs';
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
    static postProcessMessage( message, embed_link_prefix ) {
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
        let password = Buffer.from(
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
            self.parseSymmetric( this, password, secondary, true, React );

            /* Set the flag. */
            $( this ).data( 'dc-parsed', true );
        } ) );

        /* Look through markup classes for inline code blocks. */
        $( `${this.messageMarkupClass} .inline` ).each( ( function () {
            /* Skip parsed messages. */
            if ( $( this ).data( 'dc-parsed' ) !== undefined )
                return;

            /* Try parsing a symmetric message. */
            self.parseSymmetric( this, password, secondary, false, React );

            /* Set the flag. */
            $( this ).data( 'dc-parsed', true );
        } ) );
    }

    /**
     * @private
     * @desc Sends an encrypted message to the current channel.
     * @param {string} message The unencrypted message to send.
     * @param {boolean} force_send Whether to ignore checking for the encryption trigger and always encrypt and send.
     * @returns {number} Returns 1 if the message failed to be parsed correctly and 0 on success.
     * @param {int|undefined} channel_id If specified, sends the embedded message to this channel instead of the
     *      current channel.
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
            return 1;

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
                return 1;

            /* Check if it has the trigger. */
            if ( message[ message.length - 1 ] !== this.configFile.encodeMessageTrigger )
                return 1;

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
            return 1;

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

        return 0;
    }

    /* =============== BEGIN UI HANDLE CALLBACKS =============== */

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
            let password = pwd_field[ 0 ].value;

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
                        pwd_field[ 0 ].value = '';

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
                            pwd_field[ 0 ].value = '';

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
        $( '#dc-overlay' )[ 0 ].style.display = 'block';

        /* Show the upload overlay. */
        $( '#dc-overlay-upload' )[ 0 ].style.display = 'block';
    }

    /**
     * @private
     * @desc Opens the file menu selection.
     */
    static on_alter_file_button_clicked() {
        /* Create an input element. */
        let file = require( 'electron' ).remote.dialog.showOpenDialog( {
            title: 'Select a file to encrypt and upload',
            label: 'Select',
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
            file_upload_btn[ 0 ].className = 'dc-button dc-button-inverse';

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
                            file_upload_btn[ 0 ].className = 'dc-button';
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
                        file_upload_btn[ 0 ].className = 'dc-button';

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
        $( '#dc-overlay' )[ 0 ].style.display = 'none';

        /* Show the upload overlay. */
        $( '#dc-overlay-upload' )[ 0 ].style.display = 'none';
    }

    /**
     * @private
     * @desc Opens the settings menu.
     */
    static on_settings_button_clicked() {
        /* Show main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'block';

        /* Show the main settings menu. */
        $( '#dc-overlay-settings' )[ 0 ].style.display = 'block';
    }

    /**
     * @private
     * @desc Closes the settings menu.
     */
    static on_settings_close_button_clicked() {
        /* Hide main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'none';

        /* Hide the main settings menu. */
        $( '#dc-overlay-settings' )[ 0 ].style.display = 'none';
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
            self.configFile.encodeMessageTrigger = $( '#dc-settings-encrypt-trigger' )[ 0 ].value;
            self.configFile.timedMessageExpires = $( '#dc-settings-timed-expire' )[ 0 ].value;
            self.configFile.encryptBlockMode = $( '#dc-settings-cipher-mode' )[ 0 ].value;
            self.configFile.defaultPassword = $( '#dc-settings-default-pwd' )[ 0 ].value;
            self.configFile.encryptScanDelay = $( '#dc-settings-scan-delay' )[ 0 ].value;
            self.configFile.paddingMode = $( '#dc-settings-padding-mode' )[ 0 ].value;
            self.configFile.useEmbeds = $( '#dc-embed-enabled' )[ 0 ].checked;
            self.configFile.encryptMode = discordCrypt
                .cipherStringToIndex( dc_primary_cipher[ 0 ].value, dc_secondary_cipher[ 0 ].value );

            dc_primary_cipher[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, false );
            dc_secondary_cipher[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, true );

            /* Handle master password updates if necessary. */
            if ( dc_master_password[ 0 ].value !== '' ) {
                let password = dc_master_password[ 0 ].value;

                /* Reset the password field. */
                dc_master_password[ 0 ].value = '';

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
                            self.saveSettings( $( '#dc-settings-save-btn' )[ 0 ] );
                        }

                        return false;
                    }
                );
            }
            else {
                /* Save the configuration file and update the button text. */
                self.saveSettings( $( '#dc-settings-save-btn' )[ 0 ] );
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
            self.resetSettings( $( '#dc-settings-reset-btn' )[ 0 ] );

            /* Update all settings from the settings panel. */
            $( '#dc-settings-cipher-mode' )[ 0 ].value = self.configFile.encryptBlockMode.toLowerCase();
            $( '#dc-settings-padding-mode' )[ 0 ].value = self.configFile.paddingMode.toLowerCase();
            $( '#dc-settings-encrypt-trigger' )[ 0 ].value = self.configFile.encodeMessageTrigger;
            $( '#dc-settings-timed-expire' )[ 0 ].value = self.configFile.timedMessageExpires;
            $( '#dc-settings-default-pwd' )[ 0 ].value = self.configFile.defaultPassword;
            $( '#dc-settings-scan-delay' )[ 0 ].value = self.configFile.encryptScanDelay;
            $( '#dc-embed-enabled' )[ 0 ].checked = self.configFile.useEmbeds;
            $( '#dc-master-password' )[ 0 ].value = '';
            $( '#dc-primary-cipher' )[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, false );
            $( '#dc-secondary-cipher' )[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, true );
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
        $( '#dc-overlay' )[ 0 ].style.display = 'none';
        $( '#dc-update-overlay' )[ 0 ].style.display = 'none';
    }

    /**
     * @private
     * @desc Switches assets to the Info tab.
     */
    static on_info_tab_button_clicked() {
        /* Switch to tab 0. */
        discordCrypt.setActiveTab( 0 );
    }

    /**
     * @private
     * @desc Switches assets to the Key Exchange tab.
     */
    static on_exchange_tab_button_clicked() {
        /* Switch to tab 1. */
        discordCrypt.setActiveTab( 1 );
    }

    /**
     * @private
     * @desc Switches assets to the Handshake tab.
     */
    static on_handshake_tab_button_clicked() {
        /* Switch to tab 2. */
        discordCrypt.setActiveTab( 2 );
    }

    /**
     * @private
     * @desc Closes the key exchange menu.
     */
    static on_close_exchange_button_clicked() {
        /* Hide main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'none';

        /* Hide the entire exchange key menu. */
        $( '#dc-overlay-exchange' )[ 0 ].style.display = 'none';
    }

    /**
     * @private
     * @desc Opens the key exchange menu.
     */
    static on_open_exchange_button_clicked() {
        /* Show background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'block';

        /* Show main menu. */
        $( '#dc-overlay-exchange' )[ 0 ].style.display = 'block';
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

        /* Clear the old select list. */
        $( '#dc-keygen-algorithm option' ).each( ( function () {
            $( this ).remove();
        } ) );

        /* Repopulate the entries. */
        switch ( dc_keygen_method[ 0 ].value ) {
            case 'dh':
                for ( let i = 0; i < dh_bl.length; i++ ) {
                    let v = dh_bl[ i ];
                    dc_keygen_algorithm[ 0 ].append( new Option( v, v, i === ( dh_bl.length - 1 ) ) );
                }
                break;
            case 'ecdh':
                for ( let i = 0; i < ecdh_bl.length; i++ ) {
                    let v = ecdh_bl[ i ];
                    $( '#dc-keygen-algorithm' )[ 0 ].append( new Option( v, v, i === ( ecdh_bl.length - 1 ) ) );
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
        switch ( dc_keygen_method[ 0 ].value ) {
            case 'dh':
                /* Generate a new Diffie-Hellman RSA key from the bit size specified. */
                key = discordCrypt.generateDH( parseInt( dc_keygen_algorithm[ 0 ].value ) );

                /* Calculate the index number starting from 0. */
                index = dh_bl.indexOf( parseInt( dc_keygen_algorithm[ 0 ].value ) );
                break;
            case 'ecdh':
                /* Generate a new Elliptic-Curve Diffie-Hellman key from the bit size specified. */
                key = discordCrypt.generateECDH( parseInt( dc_keygen_algorithm[ 0 ].value ) );

                /* Calculate the index number starting from dh_bl.length. */
                index = ( ecdh_bl.indexOf( parseInt( dc_keygen_algorithm[ 0 ].value ) ) + dh_bl.length );
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
            key.getPublicKey( 'hex', dc_keygen_method[ 0 ].value === 'ecdh' ?
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
        $( '#dc-pub-key-ta' )[ 0 ].value = raw_buffer.toString( 'hex' );

        /* Get the private key then display it. */
        $( '#dc-priv-key-ta' )[ 0 ].value = key.getPrivateKey( 'hex' );
    }

    /**
     * @private
     * @desc Clears any public and private keys generated.
     */
    static on_keygen_clear_button_clicked() {
        /* Clear the key textareas. */
        $( '#dc-pub-key-ta' )[ 0 ].value = $( '#dc-priv-key-ta' )[ 0 ].value = '';
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
            if ( dc_pub_key_ta[ 0 ].value === '' )
                return;

            /* The text area stores a hex encoded binary. Convert it to a buffer prior to encoding. */
            let message = Buffer.from( dc_pub_key_ta[ 0 ].value, 'hex' );

            /* Add the header to the message and encode it. */
            message = self.encodedKeyHeader + discordCrypt.substituteMessage( message, true );

            /* Split the message by adding a new line every 32 characters like a standard PGP message. */
            let formatted_message = message.replace( /(.{32})/g, ( e ) => {
                return `${e}\n`
            } );

            /* Calculate the algorithm string. */
            let algo_str = `${$( '#dc-keygen-method' )[ 0 ].value !== 'ecdh' ? 'DH-' : 'ECDH-'}` +
                `${$( '#dc-keygen-algorithm' )[ 0 ].value}`;

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
            $( '#dc-keygen-send-pub-btn' )[ 0 ].innerText = 'Sent The Public Key!';

            setTimeout( ( function () {
                $( '#dc-keygen-send-pub-btn' )[ 0 ].innerText = 'Send Public Key';
            } ), 1000 );
        };
    }

    /**
     * @private
     * @desc Pastes what is stored in the clipboard to the handshake public key field.
     */
    static on_handshake_paste_public_key_button_clicked() {
        $( '#dc-handshake-ppk' )[ 0 ].value = require( 'electron' ).clipboard.readText();
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
            if ( !dc_handshake_ppk[ 0 ].value || !dc_handshake_ppk[ 0 ].value.length )
                return;

            /* Skip if the user hasn't generated a key of their own. */
            if ( !dc_pub_key_ta[ 0 ].value || !dc_pub_key_ta[ 0 ].value.length ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'You Didn\'t Generate A Key!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
                } ), 1000 );
                return;
            }

            /* Check if the message header is valid. */
            if (
                dc_handshake_ppk[ 0 ].value.replace( /\r?\n|\r/g, "" )
                    .slice( 0, 4 ) !== self.encodedKeyHeader
            )
                return;

            /* Snip off the header. */
            let blob = dc_handshake_ppk[ 0 ].value.replace( /\r?\n|\r/g, "" ).slice( 4 );

            /* Skip if invalid braille encoded message. */
            if ( !discordCrypt.isValidBraille( blob ) )
                return;

            try {
                /* Decode the message. */
                value = Buffer.from( discordCrypt.substituteMessage( blob ), 'hex' );
            }
            catch ( e ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'Invalid Public Key!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
                } ), 1000 );
                return;
            }

            /* Check the algorithm they're using is the same as ours. */
            algorithm = value.readInt8( 0 );

            /* Check the algorithm is valid. */
            if ( !discordCrypt.isValidExchangeAlgorithm( algorithm ) ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'Invalid Algorithm!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
                } ), 1000 );
                return;
            }

            /* Read the user's generated public key. */
            let user_pub_key = Buffer.from( dc_pub_key_ta[ 0 ].value, 'hex' );

            /* Check the algorithm used is the same as ours. */
            if ( user_pub_key.readInt8( 0 ) !== algorithm ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'Mismatched Algorithm!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
                } ), 1000 );
                return;
            }

            /* Update the algorithm text. */
            $( '#dc-handshake-algorithm' )[ 0 ].innerText =
                `Exchange Algorithm: ${discordCrypt.indexToExchangeAlgorithmString( algorithm )}`;

            /* Get the salt length. */
            salt_len = value.readInt8( 1 );

            /* Make sure the salt length is valid. */
            if ( salt_len < 16 || salt_len > 32 ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'Invalid Salt Length!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
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
            $( '#dc-handshake-salts' )[ 0 ].innerText =
                `Salts: [ ${displaySecret( salt.toString( 'hex' ) )}, ` +
                `${displaySecret( user_salt.toString( 'hex' ) )} ]`;

            /* Read the public key and convert it to a hex string. */
            payload = Buffer.from( value.subarray( 2 + salt_len ) ).toString( 'hex' );

            /* Return if invalid. */
            if ( !discordCrypt.privateExchangeKey || discordCrypt.privateExchangeKey === undefined ||
                typeof discordCrypt.privateExchangeKey.computeSecret === 'undefined' ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'Failed To Calculate Private Key!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
                } ), 1000 );
                return;
            }

            /* Compute the local secret as a hex string. */
            let derived_secret =
                discordCrypt.computeExchangeSharedSecret( discordCrypt.privateExchangeKey, payload, false, false );

            /* Show error and quit if derivation fails. */
            if ( !derived_secret || !derived_secret.length ) {
                /* Update the text. */
                dc_handshake_compute_btn[ 0 ].innerText = 'Failed To Derive Key!';
                setTimeout( ( function () {
                    dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
                } ), 1000 );
                return;
            }

            /* Display the first 64 characters of it. */
            $( '#dc-handshake-secret' )[ 0 ].innerText =
                `Derived Secret: [ ${displaySecret( derived_secret.length > 64 ?
                    derived_secret.substring( 0, 64 ) :
                    derived_secret )
                    } ]`;

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
                    dc_handshake_compute_btn[ 0 ].innerText = 'Both Salts Are Equal ?!';
                    setTimeout(
                        ( function () {
                            dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
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
                        dc_handshake_compute_btn[ 0 ].innerText = 'Failed Generating Primary Key!';
                        setTimeout(
                            ( function () {
                                dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
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
                        $( '#dc-handshake-primary-key' )[ 0 ].value = key.toString( 'base64' );

                        /* Since more iterations are done for the primary key, this takes 4x as long thus will
                           always finish second. We can thus restore the original Generate text for the button once
                           this is done. */
                        dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';

                        /* Now we clear the additional information. */
                        $( '#dc-handshake-algorithm' )[ 0 ].innerText = '...';
                        $( '#dc-handshake-secret' )[ 0 ].innerText = '...';
                        $( '#dc-handshake-salts' )[ 0 ].innerText = '...';
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
                    dc_handshake_compute_btn[ 0 ].innerText = 'Failed Generating Secondary Key!';
                    setTimeout(
                        ( function () {
                            dc_handshake_compute_btn[ 0 ].innerText = 'Compute Secret Keys';
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
                    $( '#dc-handshake-secondary-key' )[ 0 ].value = key.toString( 'base64' );
                }

                return false;
            } );

            /* Update the text. */
            dc_handshake_compute_btn[ 0 ].innerText = 'Generating Keys ...';

            /* Finally clear all volatile information. */
            discordCrypt.privateExchangeKey = undefined;
            dc_handshake_ppk[ 0 ].value = '';
            dc_priv_key_ta[ 0 ].value = '';
            dc_pub_key_ta[ 0 ].value = '';
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
        if ( dc_handshake_primary_key[ 0 ].value === '' ||
            dc_handshake_secondary_key[ 0 ].value === '' )
            return;

        /* Format the text and copy it to the clipboard. */
        require( 'electron' ).clipboard.writeText(
            `Primary Key: ${dc_handshake_primary_key[ 0 ].value}\r\n\r\n` +
            `Secondary Key: ${dc_handshake_secondary_key[ 0 ].value}`
        );

        /* Nuke. */
        dc_handshake_primary_key[ 0 ].value = dc_handshake_secondary_key[ 0 ].value = '';

        /* Update the button text & reset after 1 second. */
        $( '#dc-handshake-cpy-keys-btn' )[ 0 ].innerText = 'Coped Keys To Clipboard!';

        setTimeout( ( function () {
            $( '#dc-handshake-cpy-keys-btn' )[ 0 ].innerText = 'Copy Keys & Nuke';
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
            if ( !dc_handshake_primary_key[ 0 ].value || !dc_handshake_primary_key[ 0 ].value.length )
                return;

            /* Skip if no secondary key was generated. */
            if ( !dc_handshake_secondary_key[ 0 ].value ||
                !dc_handshake_secondary_key[ 0 ].value.length )
                return;

            /* Create the password object and nuke. */
            let pwd = discordCrypt.createPassword(
                dc_handshake_primary_key[ 0 ].value,
                dc_handshake_secondary_key[ 0 ].value
            );
            dc_handshake_primary_key[ 0 ].value = dc_handshake_secondary_key[ 0 ].value = '';

            /* Apply the passwords and save the config. */
            self.configFile.passList[ discordCrypt.getChannelId() ] = pwd;
            self.saveConfig();

            /* Update the text and reset it after 1 second. */
            $( '#dc-handshake-apply-keys-btn' )[ 0 ].innerText = 'Applied & Saved!';
            setTimeout( ( function () {
                $( '#dc-handshake-apply-keys-btn' )[ 0 ].innerText = 'Apply Generated Passwords';

                /* Reset quality bit length fields. */
                $( '#dc-handshake-prim-lbl' ).text( 'Primary Key: ' );
                $( '#dc-handshake-sec-lbl' ).text( 'Secondary Key: ' );

                /* Hide main background. */
                $( '#dc-overlay' )[ 0 ].style.display = 'none';

                /* Hide the entire exchange key menu. */
                $( '#dc-overlay-exchange' )[ 0 ].style.display = 'none';

                /* Reset the index to the info tab. */
                discordCrypt.setActiveTab( 0 );
            } ), 1000 );
        }
    }

    /**
     * @private
     * @desc Opens the password editor menu.
     */
    static on_passwd_button_clicked() {
        $( '#dc-overlay' )[ 0 ].style.display = 'block';
        $( '#dc-overlay-password' )[ 0 ].style.display = 'block';
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
                $( "#dc-password-primary" )[ 0 ].value = '';
                $( "#dc-password-secondary" )[ 0 ].value = '';

                /* Close. */
                $( '#dc-overlay' )[ 0 ].style.display = 'none';
                $( '#dc-overlay-password' )[ 0 ].style.display = 'none';
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
                $( "#dc-password-primary" )[ 0 ].value = '';
                $( "#dc-password-secondary" )[ 0 ].value = '';

                /* Close. */
                $( '#dc-overlay' )[ 0 ].style.display = 'none';
                $( '#dc-overlay-password' )[ 0 ].style.display = 'none';
            } ), 1000 );
        };
    }

    /**
     * @private
     * @desc Closes the password editor menu.
     */
    static on_cancel_password_button_clicked() {
        /* Clear the fields. */
        $( "#dc-password-primary" )[ 0 ].value = '';
        $( "#dc-password-secondary" )[ 0 ].value = '';

        /* Close after a .25 second delay. */
        setTimeout( ( function () {
            /* Close. */
            $( '#dc-overlay' )[ 0 ].style.display = 'none';
            $( '#dc-overlay-password' )[ 0 ].style.display = 'none';
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
                dc_lock_btn[ 0 ].innerHTML = Buffer.from( self.lockIcon, 'base64' ).toString( 'utf8' );
                self.configFile.encodeAll = true;
            }
            else {
                dc_lock_btn.attr( 'title', 'Enable Message Encryption' );
                dc_lock_btn[ 0 ].innerHTML = Buffer.from( self.unlockIcon, 'base64' ).toString( 'utf8' );
                self.configFile.encodeAll = false;
            }

            /* Set the button class. */
            $( '.dc-svg' ).attr( 'class', 'dc-svg' );

            /* Save config. */
            self.saveConfig();
        };
    }

    /* ================ END UI HANDLE CALLBACKS ================ */

    /* =================== END MAIN CALLBACKS ================== */

    /* =============== BEGIN CRYPTO CALLBACKS ================== */

    /* ======================= UTILITIES ======================= */

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
     * @param {boolean} header_present Whether the message's magic string is attached to the input.
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
                        /* If parsing or slicing somehow fails, this isn't valid. */
                    catch ( e ) {
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
            else if ( split_msg[ i ] === '@everyone' || split_msg[ i ] === '@here' ) {
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
        let url_expr = new RegExp( /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig ),
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
            data = sjcl.arrayBuffer.ccm.compat_encrypt( new sjcl.cipher.aes( params.key ), data, params.iv );

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
                require( 'request' ).post( {
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
                require( 'request' ).post( {
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

    /* ============== NODE CRYPTO HASH PRIMITIVES ============== */

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
        let _in, _salt;

        /* PBKDF2-HMAC-SHA256 Helper. */
        function PBKDF2_SHA256( input, salt, size, iterations ) {
            try {
                return Buffer.from(
                    discordCrypt.pbkdf2_sha256( input, salt, true, undefined, undefined, size, iterations ),
                    'hex'
                );
            }
            catch ( e ) {
                discordCrypt.log( e.toString(), 'error' );
                return Buffer.alloc( 1 );
            }
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
        function Script_RowMix( BY, Yi, r, x, _X ) {
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
                if ( stop )
                    return cb( new Error( 'cancelled' ), currentOps / totalOps );

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
                            Script_RowMix( XY, Yi, r, x, _X );
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
                            Script_RowMix( XY, Yi, r, x, _X );
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
                        return cb(
                            null,
                            1.0,
                            Buffer.from( PBKDF2_SHA256( input, Buffer.from( b ), output_length, 1 ) )
                        );
                    default:
                        return cb( new Error( 'invalid state' ), 0 );
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

    /*  */
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

    /* ============ END NODE CRYPTO HASH PRIMITIVES ============ */

    /* ================ CRYPTO CIPHER FUNCTIONS ================ */

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
        else
        /* Generate a random salt to derive the key and IV. */
            _salt = crypto.randomBytes( 8 );

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
        else
        /* Generate a random salt to derive the key and IV. */
            _salt = crypto.randomBytes( 8 );

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

    /* ============== END CRYPTO CIPHER FUNCTIONS ============== */

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
            case 256:
                groupName = 'secp256k1';
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
            default:
                return null;
        }

        /* Create the key object. */
        try {
            key = require( 'crypto' ).createECDH( groupName );
        }
        catch ( err ) {
            return null;
        }

        /* Generate the key if it's valid. */
        if ( key !== undefined && key !== null && typeof key.generateKeys !== 'undefined' ) {
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
        let tag = discordCrypt.hmac_sha256( Buffer.from( msg, 'hex' ), primary_key, true );

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

            /* Compute the HMAC-SHA-256 of the cipher text as hex. */
            let computed_tag = Buffer.from( discordCrypt.hmac_sha256( message, primary_key, true ), 'hex' );

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

    /* ================ END CRYPTO CALLBACKS =================== */
}

/* Required for code coverage reports. */
module.exports = { discordCrypt };
