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

/**
 * @desc Use a scoped variable to protect the internal state of the plugin.
 * @type {_discordCrypt}
 */
let discordCrypt = ( function() {
    /**
     * @desc Master database password. This is a Buffer() containing a 256-bit key.
     * @type {Buffer|null}
     */
    let _masterPassword = null;

    /**
     * @desc Message scanning interval handler's index. Used to stop any running handler.
     *      Defined only if hooking of modules failed.
     * @type {int}
     */
    let _scanInterval;

    /**
     * @desc The index of the handler used to reload the toolbar.
     *      Defined only if hooking of modules failed.
     * @type {int}
     */
    let _toolbarReloadInterval;

    /**
     * @desc The index of the handler used for automatic update checking.
     * @type {int}
     */
    let _updateHandlerInterval;

    /**
     * @desc The index of the handler used for timed message deletion.
     * @type {int}
     */
    let _timedMessageInterval;

    /**
     * @desc The main message update event dispatcher used by Discord. Resolved upon startup.
     * @type {Object|null}
     */
    let _messageUpdateDispatcher = null;

    /**
     * @desc The configuration file currently in use. Only valid after decryption of the configuration database.
     * @type {Config|null}
     */
    let _configFile = null;

    /**
     * @desc Used to cache webpack modules.
     * @type {CachedModules}
     */
    let _cachedModules = {};

    /**
     * @desc Stores the private key object used in key exchanges.
     * @type {Object}
     */
    let _privateExchangeKey;

    /**
     * @public
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
             * @desc Used to scan each message for an embedded descriptor.
             * @type {string}
             */
            this._messageMarkupClass = '.markup';
            /**
             * @desc Used to find the search toolbar to inject all option buttons.
             * @type {string}
             */
            this._searchUiClass = '.search .search-bar';
            /**
             * @desc Used to hook messages being sent.
             * @type {string}
             */
            this._channelTextAreaClass = '.content textarea';

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
                `eNqtWWmPG8cR/SsNBsin6VF39e1IBhzGyQJeBUaEEIm/GKtZZsmI4h6kKGl/fd6rGe4hybYkB+L29FHdVV13tZ6+fLPfX27N/v3V8tlsHMzM+vzZ7Hyww2Z99fLy7ObcvrnaXJ6d25d7LO727zeEPRteXdxcvtme2+Fyc3nzjdnfnG13V2c3y+3+TzOzX+8J9k/dab7fDjfvr/bLczM/Hjr71jzdHS7Mu2czd/VuZt5P37fr8/3q2Sy4mVkt1xer/dg/rJdv/3xJYOOMr/jNzLA52+2UVByE88zTq7P9yvxnvdk8m2249+Jm+X5mcJ3nPpi4suFg0Xp38HGVD7JCz7aNDTbcPg/Gr+LBr2w8WH/73CdjjE8rWzF0q3QIq3AotzyoHKxsxMjKyu3sCe7xBPi/ffpk5N+3T3+NqSBu+X9h5F9x0JGHjxlxZKHEexay/5iFpYk2s4/4dcdI8q3kakIlS6Su2BzYwd/tazSGE59Y4ojs+/Tqr2wsztlQ6zUg8Is8pOS9OFMB5JNcOxOdxVKue5sJhANCjNc24laYwdoef+jh+OzcteOKTux1dVVbvsaUMTzUiNuXDESgOcZoJcZDKHmFv2uI3UqzIjZ66IgP/MOs8Bc9Fm5fgzVQEr2LE6hW9FlJMR8Rg5X7u9r76ycvB59C5v0dqMhSbBG/8a6YENs1SCymmiSkN2CpV8UMpU9762vAMMU+jV2rXcJYhcDtJZlqsVu8zVBxAX9bHnEfqSntWnh8aHryXgIwU4jRm5jTdQpYbI6Htj2PtTHZ43ea16/Bl/MmJnP8TvO3qlZPqFdfZjC75X6/3l7svsZo/rLeDZc353OajHkxHfQLRrPcnr2kad6d/Gy2Xb41tJUg+MF+lje79eX22cz3/gNrmiDuLE892Z3t6ejd6803IHAAWVc3y93y5rC8t7TpWrTEb/5wHvgPtzBqgVI77058VXe18O7WPPeRU3BW7m4qSOdO3IFSTX3ydfB9Bpj00fsOJ8U+ZN+FvrXWlT5W6eIQ+1a8db1z0lWsVBt7J62DMLFjcFgKWQgAnXR98ZX93KxnewqUIgulx3UgTg5yAnIEExljDrOOZBoJRwbj0Enraw3EYkNf3UhFs7mvJWPG1ch+TdqGYVxVyO5uteTuHiYNoS+4m0JyvkReW4EVLIzAmJsTOZYl647jZ5o80ka6m7KLRlH6EOsAKpNywmXwQGJAGySiBRzaGhaeTgDDQW8UOqffMn59R8+w+2CKsvWQWR4sxSWdis7GTmWGL+UFHmDepYgbelALCWBrn0Avrwne5pUU0rEYiaVOuI7ULGQVF1Ej1eepG3oCjw8cDuEQ1OSg18kBrXhqhIflOxCrM9rPLm9gGLVYbTf4wOVpmzjwOXVsswodu/QY4QExiU5QC3Ijg6XFhYdzhGsEdhnhVbiZOhhjJhsS+zkJCQaA4oTP0nbET5TEzxlijxNyDy5jh1Ncjv0IMfIMMjWnMNmbIgfWEgg+Yi0KXtqEtSXuaPXhHcOGaIMiH7lSR66oWUF+PMJT9n1oKtHKmeySokkLqSeUAPGnQe+u/K/ErNzG3Uf8OXmlG1hEVQetYo+jAEgWRcZ2wu51h8vKAfaj6PWKctOfCHVH5Kj7Evs46nMdyXA8LTZlfiG3k9NWrTSMcLxNmeC6Owg3kTAC0DxGAAUm2Ag6V5QFtgjIeveZJkfCRqq+OP3aXA6vviSSPPn1464QQt5+VWL8I3ciNv1WWPrtoPPLMeez7N3DRbqKiAHOmlNPAYwjZhYfj+MddNbVaUQ9aea0jtClcZ3wuc8hwGuV1EntQ0kxg+x5gsv1MHU63AbNzBVWqFEqSnM8Q+fFpeqRBvWpuUaV5xkVORq8yGnos2RXfAicjr5khxvMpS+1Cc5F/lFdKY6xTIjPZamZdIkvMSWPc++JS3fEnXpS52KEZYM54isMT+MGFkBdpef10kuKqbWC9O/IBE/bd5JTfTjpdOM0yj2yVedyyqhg4I8kwdzVgxuRI1DALRKjUfJwW0F5+4kD7ieJ48EI9pJBWojmwTHg4z0GDWnYA1NEKpDEc9m3vqTQkEh2HjHRl+K10LrnRn7AjdNPL5yif6SjKdBRX7xy9jiKGD3WvPBQl+SD5Z/UIx0PjoYuAmLMCQ5bvbrco4VooC24yMNJcuhuVEh5za428+Cc/JhBGXJrTA0CFKpTeX28/X5S5Vw/QYQxD44BrY/ucfpo9NPoWF6hCPtCv7Z8N6zOthdfVVr+sHxvvp/2m+fL7Zsvd0Wl4ve7XRFiAMqXk8ycUJjLWZgrYivywi4vUmKIQfoXEDhh0Ggz/61yHsZJ12Wr8PhmpMVaKc0LBSZdSQoDBN2IB0EOneSIUYFx0IJDzVETaqguw4cgCSmDRmLQw4AVkGGELvA9IBxsmJOuLldYUofqy2fd1d3tHzPejKCF1BU+8SRo9bWytNd2QPJapNEyJMPWgX4DN1JEVQifBfeMFMFYQ+4ieCP1NOP8HHTD6bSCvA8mu4BGp+PpHk51pd3FuO+LA+b1mzUi5lep11G//rbcLm/O9kvzRwS77bn5O8qqH9+83KwH84M+N3ysbGY9XG6/G/brw9J+98P5z/+91hnr/+Hbzyfaf352c7HeWvn3v17Fv1KDPnxIeqSgcMnp9ysoYkrJRSuGoMk6ansYeoNCYCFbqFiTqV8pV9RQiIC+dFhB8c4Eja8HO3R0ptMZTYqg2KJpYoBW5j7mpgeljgdpdhkK6w1ErgE+Q9hHVByLHB9Yu0XklWMfCl+QuFqWgpErNfM1Q387/HXHKbotxc6w6Zm8IlSANODlSawVpcTThxf/3EIiZfKnC7AMn5g+wgNqgp/AM2bE0NrGYi8GZrSJVQIDLGgTQXAKBeswWF6Wx3QRuYgIe8wUHC0KVwT/wYnSomVx67VtY59WEEoh7pxRlwA2oIYhQzL4F088TJHnNI3umdYUYoEnRh7MzAShFO1JU/tn6TU5gKIOwJd5pv/ICS4FsxhI19Cs4jDBq3QoOgT5YDVzJUaE2Q3MG6yuTMHNwJuxQHGB9a0gzcUMnAgqD82JEw+MWsiPipK1CqI7K5H3DziwsjaxTEKQQicIDvplYkQyAJFWOo5Ui/bAM/ou3FaVb8453KPWDtuilC404MR9HopwfHeIba4t1gMzjTSWX8mRV8mhXNQnVjnEE60ZuA6tU3KLfpUHnqXQHEdDoWMDG2LkAOwLHuyb9nVeCx7IofOL2EABiBqph8pSqrwDOSSV5RsCbmfAKfhHuE1kjPTILauBqfDJ14iyndkeJVkyTAXyY0VVkLp0EQlTCIuQVIaskfiEkrXgDlHfHkBnH107RUIcIOPQVggeObKunYcE5nMOrp5MrLTITOa2WudBiXdIjie4CDVieyJtZRMKzoR/KN8QNiRBS5G/ghVZ7WbK2mCO+grTqC5arcKrGwahAtsAIpoxucSXiTr1mshiZNvnGi+TanqzeID/cmWOcQiq6SZENRKwnXdEPKsrPpxb0ZdzvvSwixbKUbTiBddE619oFJ+YUDsnS0UTtd/Qqr4oBdplbDQTz0cdXzTw1mTVPLAKjabvCHz+yfSn0IA6PSL5pIU43F1iWUr3lQLgBNl6hqLXOZwYBCPjownfdnhJkAMzCvqKMt5YH04gnsq0tlIX+S4M5eFrWvCNdGRmELkU9Iuo/VYnqotgCQTWtL6nJ6Xv4lNRexHVUJgqO+yG36+j21XeFN8IjNIcpxfwCXadToPWwC3FRQire08F7aFRUCYQgqgpau+AqONkQ39Xm76ZpDksrIpo2Rz12skpExyM4eE9H2qGagByLxlkfCjo4uhj8Y27yd3qv51VPWz6XPUi8A0OxZQqvYyPfUxM8kCnFGhMHb0+rtXJzk5dqwMZh/jKC6hY5btB7nT3bystCTaBObp5beCcEfHPDJjC/+jonMENHo2RT7pPJEL/A7pkcCw=`;

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
                'currify.js': {"requiresElectron":false,"requiresBrowser":true,"minify":true,"code":"eNqdVFFv2yAQ/iuONaWgEit5jUujae2etvZlfbKs1rWhYaLgYWgWOfz3gcFOKuWh3Ys5HXcfd9995xk1otZMCiBgzyhI5fNvUusUY71viaQJ+dtKpbv5PDWiIZQJ0qSz8fJVNoYTGI4shmIBYE54RxKPN+IfEQPKfB7OrHptYDBBUSIRUntOdKJyoPC5Z3dMNHK3Ccf6XMQLl88V34TjbERHON34z1pvWQez2ijF6N4Xby2YWIH9W6USgRQiuSLaKJGMd4kAzos07CePBBSZgccZKWgZLDVYHqbGZ+hQ5I9hyvERjdznmPm8hvG92oHOltD72ehj0edRORZkl9wqJRV4+lYJIXXimm3idJKLLz21F08w11sldwnPatkQnP68v3n4cft4d//r8fv9w91Nirj1cC32peM+TnPdW5v7FoplmdUV56AdB41OteNTCR4CV2UhypEtCcjhIKBFLTomDnw65mwM8i+Ol0MR7ENMUdexF4rAy1xc6YwT8aK3ubi8hBJoVwScqrCgjxNeF8eyfRmwT43TaqcVc7ofGNX4dMawDyDFabsRV2VV2/I9eJOsSZaoUi/mlQjduX5PXiGfjfei+mwGkv+Tg9gHskqbn0g8/iim+UwrJWBQWJBiSkXSbaXhTfJMpqWZpW7o05/iPc1+nEFG09txpIjhr0pVe0CuVxuyWK2XEFG8yumVE4GbNivoYlUe05yc/LpIh4pYxLjGKlrwfMMsrJM5VkXARI54H1sotwxS1JUGDA2lZa2SWnomso6zmoRdOZIIHfn1VMJirGqxQnwUqQYGFnV5OBhrUe9Ydx9UpFG3aQnBZEML838pAQw+"},
            'curve25519.js': {"requiresElectron":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'openpgp.js': {"requiresElectron":true,"requiresBrowser":true,"minify":false,"code":"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"},
            'sha3.js': {"requiresElectron":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'sjcl.js': {"requiresElectron":true,"requiresBrowser":false,"minify":true,"code":"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"},
            'smalltalk.js': {"requiresElectron":false,"requiresBrowser":true,"minify":true,"code":"eNqtWAlz4rgS/ise72zWrhhjCDnGjplHGHJPrpkcs3lTFWELULAlR5YDhOG/v5ZswAnZ2t2qFxIbyS2p++uvD+dDL6OBIIwa5lTPUqylgpNA6F7AaCo07N/r5yf6T0vkXyy9jWiAI5ihfssYWLqdxiiKBIqGumkhH/vNab5U+NNnFGXYxTOPY5Fxqi3Owua0mEK8n8WYitSOMO2LwWdD2GqZjy1susVgNvPmazVmCIsu1gdyZOm6ha1poFRzP9Rm5mwhHhkYBJAPIswsVIt8bjDTIj5bW2N2NxOC0V+/hJX638B62jeQaXOcRCjARlWv9i197SljwgMLQ/9hl9AkA/smCfb1j9Nopmu5xjBIYRAigSoUxTDxmFaUsN588BYKS31Ci4A6Sy1JrmXJLJybJWByKcYN7E9nhRlTqYErZj4u9tYTlKYjxkPd933xeTl0dYHHQl/uk8L2Ij8wR4T5Ymnxf6k0ebfLm7pZbP2wG5JnLYhgRx/27WO9qWZe2xpELMX6XEyNKjm6IF4F+ebuAKMQ8+bHKZ7tVotBeW9QRwAdKohjpIMYm32c0lmxuCSHlCGFWPlBfl5F0jjRm9rHKbJjlBjSYNNvPuzmzzWBuoSGeOx/nIrZGzNAOVuwUzbCvI1SbJgzvVA4X9x8MO1HRqih6+ZctdL1YYlzUODMrGiONPGRYVpcXQM/ZIGivx2AIQJ3IixHhg77ANkSCLqc1BB4ObiWzoYQfJlP8Ui74CwmoGBhXHEC9aO1tQ+Rna8E6hvy2cwDjsHBBv2MXGHOzAUhbUIp5offv576c15AcAS2AvRMgbKMcWuhcZeFExslCaZhe0Ci0AhMq2sE1r3U0NJz3v807R7jHRQMgLlNDIMgSw1zLvmeEICfYvENR1hheIVoHxuORYsEAZpbYwPQIAEcE1iJBWt6BngMUgkWMEMkvnCGCQcUYjmtxgIUz/Sf5dMCG4Vh5xkMOiUpMA9DiFkSsH9siimxWtlEH+JJyEYUVMw4J72JEZpGWbdsyZJQoY7K+WnaOfveuXJrG1bnW9utb1vfW3vuJ+u0s//d3di2ri/cjR3r6ujgEIafrC/nt2duw5nJjGbDwW0WYqAYm2OS+oUlCzIVJgEDu3B4aqoYSUwvHREBBhLQBJivRXauR8/gltLRtJidcCxN/YJ7KIuEYXpd4O7Qmy8AfaGYWOjtA2kBs9MB6YkTPFlb68PBQJni9pfbhvnYvdcj3BOgOif9gbxnCVwUxOBQEgnpOb9JIPVF9zJ+r4GaRfyWXKdiIVNnQpUAfQRLIIwgpaG8Ci7dkpTKFLYBx5aApAIpAEN8zhOGvqwUMnWASnppi0xF5iIuF7Ejs9fzPNohQhODAgR+lQ1/5S6q2gKnAuqQFUFmzplfqYF/wcS5F8FS/Fn61Z3PeKRnFK6Fh+jXrw8R/DEzN6Io6dwnsK8n/X7PV0KvYDVgk0vHfpFchDrOccV6bVmL+//OvpIl0iyVgM970krix4ZMksBacU9+vqvdMuSWAPdWQ+dfuUoiVlWZ9TXwkVmABu2GaT0zEmrADW+ewrvQdZSyF8dhFizScNGzWDSLItNDEEzWK151c9CK/YUKPSHNe8own+SJj3Hj4f5tVRIz/eeDaZbYjkvbjpc1vatapAV2Qur0TppDZSQHku3zzm3hyNcqYdMTdgI1l4rCt2B6zJ5xXgBEabsW7G/b9sJOGXfYUDOzj4YuKz/4Iy8fhr6bikmEm8techqSFFw1cXsRHnsoIn1aIQLHqRvAqZh7cr4SEp4XCTdgURZT7zFLBeTaStFFzIUFRzQlSrDuOHGqQbwHREy8LoN6HruOJ3ML3MAU3ovYyEWZYF4CmEE3CGuSsZewYoceGePQU1kIVkD6gOtLRXHZrTnwM1uaoa1rJZtKamCZE2upNzeTMorL62zZY0270LxhXuEoJFnqboAWXRQM+5xlNHRHAwAELBhX0gGCPOg6WiMZa3UQ0zbhj/e7COqmlv/adRPuWh0ebK0+rG1KbkeMu79tbGx4MaGVEQnFAIqKsr0AwlmiwHGEZIwvTHdm/4lxSJDGaDTRUuhnMHT3NNSMGI2L3bRNuZ05XTF0eaAzW4FBa2p2uZeclkDQMh4Zf8hAcUkMstWE9gGkFG81LHKzd341ck4O+qwFP2ffrged67782pCX83brEm7t2iW+QXLiehh1Lm+uGndPdxc/LnnrqDVo/bit9u/CnbPj8XeW3DylB52B6K2ffqp2rq7rw+rht6/7l8lJ8OMYn+0ffdrDzmn7K3ncCX5MHh83O4dH5Plgbzg67fHu3cbR/s7FUxbfxPRL0jlYx1/SE9K9OKgfj+Tpe8dX15sdPjzu9/u+/4epUVaBdAVdoVaweIAV52qNMhtRNwXqAxFyQm7DM0lJec8BVeILfv4tuO5AxkAJ4orC1f0/4kyvC5zZ7eXl5Vb7sjXex6PH4fHwa3ty1z+++DrcbpEfwctkD//Zad1ttU4CcXCEzta7Yl3w4aeROLgMqkfDAWUnB+OnJ3I7Pv/2J4pQcrv/59YNP7r+0hmnZw7aPL7ae/p0ym7OrxzcufzKOoMT8nI3GKTUSWpp+/aGbbdH573a1URcnO60L55H2d41Ozzdyvr4ZMNp33ypfX862b6pDsIEr9+ctQeD85ebnfEtnVTXxyw93N/Z3N65rR7GQe38vL0xit/15Srq+ZvPdJFvBiQMMfVkj1pZTOIoIklKUk+FeiWFpIUhU4w4SrxlUKmY8uDVnVdSlahVMimHcw+yYSUlL9it1Z3f8+EoJ1OXRSHsxfuEyugu4lxyRqspLkmFivyitIAcUpNZJhmvGmWXX97+qW3zM7fmR66kmHcOKr39TVeUnhVpQtnZQzGJJu51N6Mis7QWJyiytBQSMaAFffmrzRdfrdJssZtMUUUE1nFcTpE4nq2Ky8qGuGwpcnes+GclwiJCYUWlL7O9fAf8DYfyY2nFF21j53cYqO9QiPPa4EpnQAaA/uR1Snfs+uZcaF5A6rKAlOuFXOysLHR2oFQQCi9hS2fnQvXNTUtbXhx7e1k3Go2GYpZL6ACAFQtWFac4r7hUOtuoN+DY+cVcxdJ1KzF7qajmr6LeVYvC6DrvCGOKuhEO3bwFnf4DmLflR8Ksvsxh3pYfs4yXclvZiHeLtmaX/wPxuo9507RwNlrpWJQI9ER/sy+k7TkvFcwV1cDUnNdhqRrUaVEHHAj9FdL81u3Jz18RhbzIyCoewszfOtt7Eybz4JS9C8uEBH8FtjeOU3623lrx+nG5lSq0U5ppqr3zylOupNg2+LfWaEjeNszXiujwChqxLoqWJ/pTFGEuXGYlnMWJcCML3NMjPHbJzDrvPoL/7B40OC/YeLvWnMFrwv8AXbJaag=="},
            };

            /**
             * @desc Oddly enough, you're allowed to perform a prototype attack to override the freeze() function.
             *      So just backup the function code here in case it gets attacked in the future.
             * @type {function}
             */
            this._freeze = Object.freeze;
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
            return '1.4.3';
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
                    'Hi There! - _discordCrypt',
                    "Oops!\r\n\r\n" +
                    "It seems you didn't read _discordCrypt's usage guide. :(\r\n" +
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
            if ( !_discordCrypt._shouldIgnoreUpdates( this.getVersion() ) ) {
                /* Check for any new updates. */
                this._checkForUpdates();

                /* Add an update handler to check for updates every 60 minutes. */
                _updateHandlerInterval = setInterval( () => {
                    self._checkForUpdates();
                }, 3600000 );
            }

            /* Get module searcher for caching. */
            const WebpackModules = _discordCrypt._getWebpackModuleSearcher();

            /* Resolve and cache all modules needed. */
            _cachedModules = {
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
            for ( let prop in _cachedModules ) {
                if ( typeof _cachedModules[ prop ] !== 'object' ) {
                    global.smalltalk.alert( 'Error Loading _discordCrypt', `Could not find requisite module: ${prop}` );
                    return;
                }
            }

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

            /* Setup Voice. */
            this._setupVoice();

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

            /* Unhook switch events if available or fallback to clearing timed handlers. */
            if ( !this._unhookMessageCallbacks() ) {
                /* Unload the toolbar reload interval. */
                clearInterval( _toolbarReloadInterval );
            }

            /* Unload the decryption interval. */
            clearInterval( _scanInterval );

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
                global.bdplugins[ '_discordCrypt' ] &&
                global.bdplugins[ '_discordCrypt' ].plugin
            ) {
                Object.freeze( bdplugins[ '_discordCrypt' ] );
                Object.freeze( bdplugins[ '_discordCrypt' ].plugin );
            }

            /* Inject application CSS. */
            _discordCrypt._injectCSS( 'dc-css', _discordCrypt.__zlibDecompress( this._appCss ) );

            /* Reapply the native code for Object.freeze() right before calling these as they freeze themselves. */
            Object.freeze = this._freeze;

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
                        _discordCrypt.aes256_decrypt_gcm( config.data, _masterPassword, 'PKC7', 'base64', false ),
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
                if ( !_configFile.hasOwnProperty( prop ) ) {
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
                    _discordCrypt.aes256_encrypt_gcm(
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
            if ( !( prim.val() !== '' && prim.val().length > 1 ) )
                delete _configFile.passList[ _discordCrypt._getChannelId() ];
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
         * @desc Debug function that attempts to hook Discord's internal event handlers for message creation.
         * @return {boolean} Returns true if handler events have been hooked.
         */
        _hookMessageCallbacks() {
            /* Find the main switch event dispatcher if not already found. */
            if ( !_messageUpdateDispatcher ) {
                /* Usually ID_78. */
                _messageUpdateDispatcher = _discordCrypt._getWebpackModuleSearcher().findByDispatchNames( [
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
         * @desc Removes all hooks on modules hooked by the _hookMessageCallbacks() function.
         * @return {boolean} Returns true if all methods have been unhooked.
         */
        _unhookMessageCallbacks() {
            /* Skip if no dispatcher was called. */
            if ( !_messageUpdateDispatcher )
                return false;

            /* Iterate over every dispatcher. */
            for ( let prop in _messageUpdateDispatcher._actionHandlers ) {
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
            cancel_btn.click( _discordCrypt._onMasterCancelButtonClicked );
        }

        /**
         * @private
         * @desc Performs an async update checking and handles actually updating the current version if necessary.
         */
        _checkForUpdates() {
            const self = this;

            setTimeout( () => {
                /* Proxy call. */
                try {
                    _discordCrypt._checkForUpdate(
                        ( file_data, short_hash, new_version, full_changelog, valid_sig ) => {
                            const replacePath = require( 'path' )
                                .join( _discordCrypt._getPluginsPath(), _discordCrypt._getPluginName() );
                            const fs = require( 'fs' );

                            /* Alert the user of the update and changelog. */
                            $( '#dc-overlay' ).css( 'display', 'block' );
                            $( '#dc-update-overlay' ).css( 'display', 'block' );

                            /* Update the version info. */
                            $( '#dc-new-version' ).text(
                                `New Version: ${new_version === '' ? 'N/A' : new_version} ( #${short_hash} - ` +
                                `Update ${valid_sig ? 'Verified' : 'Contains Invalid Signature. BE CAREFUL'}! )`
                            );
                            $( '#dc-old-version' ).text( `Current Version: ${self.getVersion()} ` );

                            /* Update the changelog. */
                            let dc_changelog = $( '#dc-changelog' );
                            dc_changelog.val(
                                typeof full_changelog === "string" && full_changelog.length > 0 ?
                                    _discordCrypt.__tryParseChangelog( full_changelog, self.getVersion() ) :
                                    'N/A'
                            );

                            /* Scroll to the top of the changelog. */
                            dc_changelog.scrollTop( 0 );

                            /* Replace the file. */
                            fs.writeFile( replacePath, file_data, ( err ) => {
                                if ( err ) {
                                    _discordCrypt.log(
                                        "Unable to replace the target plugin. " +
                                            `( ${err} )\nDestination: ${replacePath}`,
                                        'error'
                                    );
                                    global.smalltalk.alert( 'Error During Update', 'Failed to apply the update!' );
                                }
                            } );
                        }
                    );
                }
                catch ( ex ) {
                    _discordCrypt.log( ex, 'warn' );
                }
            }, 1 );
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
            if ( $( '#dc-passwd-btn' ).length !== 0 )
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
                dc_svg = $( '.dc-svg' );

            /* Set the SVG button class. */
            dc_svg.attr( 'class', 'dc-svg' );

            /* Set the initial status icon. */
            if ( dc_lock_btn.length > 0 ) {
                if ( _configFile.encodeAll ) {
                    dc_lock_btn.attr( 'title', 'Disable Message Encryption' );
                    dc_lock_btn.html( Buffer.from( this._lockIcon, 'base64' ).toString( 'utf8' ) );
                }
                else {
                    dc_lock_btn.attr( 'title', 'Enable Message Encryption' );
                    dc_lock_btn.html( Buffer.from( this._unlockIcon, 'base64' ).toString( 'utf8' ) );
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
            $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );
            $( '#dc-settings-scan-delay' ).val( _configFile.encryptScanDelay );
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

            /* Handle Database Import button. */
            $( '#dc-import-database-btn' ).click( _discordCrypt._onImportDatabaseButtonClicked( this ) );

            /* Handle Database Export button. */
            $( '#dc-export-database-btn' ).click( _discordCrypt._onExportDatabaseButtonClicked( this ) );

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

                /* Retrieve the channel props for message parsing. */
                let modules = _discordCrypt._getReactModules( _cachedModules );

                /* Encrypt the parsed message and send it. */
                if ( !self._sendEncryptedMessage(
                    modules.MessageParser.parse( modules.ChannelProps, $( this ).val() ).content
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
            let local_fingerprint = _discordCrypt.sha256( Buffer.from( $( '#dc-pub-key-ta' ).val(), 'hex' ), 'hex' );

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
         * @param {ReactModules} react_modules The modules retrieved by calling _getReactModules()
         * @returns {boolean} Returns true if the message has been decrypted.
         */
        _parseSymmetric( obj, primary_key, secondary_key, as_embed, react_modules ) {
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
                        _discordCrypt.log( 'Could not locate HighlightJS module!', 'error' );
                }

                /* Decrypted messages get set to green. */
                message.css( 'color', 'green' );
            }
            else {
                /* If it failed, set a red foreground and set a failure message to prevent further retries. */
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
        _postProcessMessage( message, embed_link_prefix ) {
            /* HTML escape characters. */
            const html_escape_characters = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;',
                '/': '&#x2F;',
                '`': '&#x60;',
                '=': '&#x3D;'
            };

            /* Remove any injected HTML. */
            message = message.replace( /[&<>"'/`=]/g, x => html_escape_characters[ x ] );

            /* Extract any code blocks from the message. */
            let processed = _discordCrypt.__buildCodeBlockMessage( message );
            let hasCode = processed.code;

            /* Extract any URLs. */
            processed = _discordCrypt.__buildUrlMessage( processed.html, embed_link_prefix );
            let hasUrl = processed.url;

            /* Extract any Emojis. */
            processed = _discordCrypt.__buildEmojiMessage( processed.html, this._emojisClass );
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
            let React = _discordCrypt._getReactModules( _cachedModules );
            $( this._messageMarkupClass ).each( ( function () {
                /* Skip classes with no embeds. */
                if ( !this.className.includes( 'embedDescription' ) )
                    return;

                /* Skip parsed messages. */
                if ( $( this ).data( 'dc-parsed' ) !== undefined )
                    return;

                /* Try parsing a symmetric message. */
                self._parseSymmetric( this, primary, secondary, true, React );

                /* Set the flag. */
                $( this ).data( 'dc-parsed', true );
            } ) );

            /* Look through markup classes for inline code blocks. */
            $( `${this._messageMarkupClass} .inline` ).each( ( function () {
                /* Skip parsed messages. */
                if ( $( this ).data( 'dc-parsed' ) !== undefined )
                    return;

                /* Try parsing a symmetric message. */
                self._parseSymmetric( this, primary, secondary, false, React );

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
            const escapeCharacters = [ "#", "/", ":" ];
            const crypto = require( 'crypto' );

            let cleaned;

            /* Skip messages starting with pre-defined escape characters. */
            if ( escapeCharacters.indexOf( message[ 0 ] ) !== -1 )
                return false;

            /* If we're not encoding all messages or we don't have a password, strip off the magic string. */
            if ( force_send === false &&
                ( !_configFile.passList[ _discordCrypt._getChannelId() ] ||
                    !_configFile.passList[ _discordCrypt._getChannelId() ].primary ||
                    !_configFile.encodeAll )
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
            let parsed = _discordCrypt.__extractTags( cleaned );

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
                    _cachedModules,
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
                        _cachedModules,
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
         * @desc Sets up the plugin's voice hooks.
         */
        _setupVoice() {
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
                    _discordCrypt.log(
                        `Failed to patch prototype: ${Array.isArray( name ) ? name[ 0 ] : name}\n${e}`,
                        'error'
                    );
                }
            };

            /* Retrieve the scanner. */
            let searcher = _discordCrypt._getWebpackModuleSearcher();

            /* Remove quality reports. */
            patchPrototype(
                '_sendQualityReports',
                () => {
                    _discordCrypt.log( 'Blocking voice quality report.', 'info' );
                },
                searcher.findByUniquePrototypes
            );
        }

        /* ========================================================= */

        /* ================== UI HANDLE CALLBACKS ================== */

        /**
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
                _discordCrypt.scrypt
                (
                    Buffer.from( password ),
                    Buffer.from( _discordCrypt.whirlpool( password, true ), 'hex' ),
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
         * @desc Cancels loading the plugin when the unlocking cancel button is pressed.
         * @return {Function}
         */
        static _onMasterCancelButtonClicked() {
            /* Use a 300 millisecond delay. */
            setTimeout(
                ( function () {
                    /* Remove the prompt overlay. */
                    $( '#dc-master-overlay' ).remove();

                    /* Do some quick cleanup. */
                    _masterPassword = null;
                    _configFile = null;
                } ), 300
            );
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
                users = _cachedModules.UserResolver.getUsers();
                guilds = _cachedModules.GuildResolver.getGuilds();
                channels = _cachedModules.ChannelResolver.getChannels();

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

                        copy_btn.text( 'Copied' );

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
                            `Your Fingerprint: [ \`${id}\` ]:\n\n`,
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
                        if ( !self.configFile.passList.hasOwnProperty( e.id ) ) {
                            /* Update the number imported. */
                            imported++;
                        }

                        /* Add it to the configuration file. */
                        self.configFile.passList[ e.id ] = _discordCrypt._createPassword( e.primary, e.secondary );
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
         * @param self
         * @return {Function}
         */
        static _onExportDatabaseButtonClicked( self ) {
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
                let data = { _discordCrypt_entries: [] },
                    entries;

                /* Iterate each entry in the configuration file. */
                for ( let prop in self.configFile.passList ) {
                    let e = self.configFile.passList[ prop ];

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
            };
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
                self.configFile.passList = {};

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
                    dc_master_password = $( '#dc-master-password' );

                /* Update all settings from the settings panel. */
                _configFile.encodeMessageTrigger = $( '#dc-settings-encrypt-trigger' ).val();
                _configFile.timedMessageExpires = $( '#dc-settings-timed-expire' ).val();
                _configFile.encryptBlockMode = $( '#dc-settings-cipher-mode' ).val();
                _configFile.defaultPassword = $( '#dc-settings-default-pwd' ).val();
                _configFile.encryptScanDelay = $( '#dc-settings-scan-delay' ).val();
                _configFile.paddingMode = $( '#dc-settings-padding-mode' ).val();
                _configFile.useEmbeds = $( '#dc-embed-enabled' ).is( ':checked' );
                _configFile.encryptMode = _discordCrypt
                    .__cipherStringToIndex( dc_primary_cipher.val(), dc_secondary_cipher.val() );

                dc_primary_cipher.val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, false ) );
                dc_secondary_cipher.val( _discordCrypt.__cipherIndexToString( _configFile.encryptMode, true ) );

                /* Handle master password updates if necessary. */
                if ( dc_master_password.val() !== '' ) {
                    let password = dc_master_password.val();

                    /* Ensure the password meets the requirements. */
                    if( !_discordCrypt.__validatePasswordRequisites( password ) )
                        return;

                    /* Reset the password field. */
                    dc_master_password.val( '' );

                    /* Hash the password. */
                    _discordCrypt.scrypt
                    (
                        Buffer.from( password ),
                        Buffer.from( _discordCrypt.whirlpool( password, true ), 'hex' ),
                        32,
                        4096,
                        8,
                        1,
                        ( error, progress, pwd ) => {
                            if ( error ) {
                                /* Alert the user. */
                                global.smalltalk.alert(
                                    '_discordCrypt Error',
                                    'Error setting the new database password. Check the console for more info.'
                                );

                                _discordCrypt.log( error.toString(), 'error' );
                                return true;
                            }

                            if ( pwd ) {
                                /* Now update the password. */
                                _masterPassword = Buffer.from( pwd, 'hex' );

                                /* Save the configuration file and update the button text. */
                                self._saveSettings( $( '#dc-settings-save-btn' ) );
                            }

                            return false;
                        }
                    );
                }
                else {
                    /* Save the configuration file and update the button text. */
                    self._saveSettings( $( '#dc-settings-save-btn' ) );
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
                $( '#dc-settings-default-pwd' ).val( _configFile.defaultPassword );
                $( '#dc-settings-scan-delay' ).val( _configFile.encryptScanDelay );
                $( '#dc-embed-enabled' ).prop( 'checked', _configFile.useEmbeds );
                $( '#dc-master-password' ).val( '' );
            };
        }

        /**
         * @private
         * @desc Restarts the app by performing a window.location.reload()
         */
        static _onUpdateRestartNowButtonClicked() {
            /* Window reload is simple enough. */
            location.reload();
        }

        /**
         * @private
         * @desc Closes the upload available panel.
         */
        static _onUpdateRestartLaterButtonClicked() {
            /* Hide the update and changelog. */
            $( '#dc-overlay' ).css( 'display', 'none' );
            $( '#dc-update-overlay' ).css( 'display', 'none' );
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
                    _discordCrypt.sha512( isUserSaltPrimary ? user_salt : salt, true ),
                    'hex'
                );
                let secondary_hash = Buffer.from(
                    _discordCrypt.whirlpool( isUserSaltPrimary ? salt : user_salt, true ),
                    'hex'
                );

                /* Global progress for async callbacks. */
                let primary_progress = 0, secondary_progress = 0;

                /* Calculate the primary key. */
                _discordCrypt.scrypt(
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
                _discordCrypt.scrypt( secondary_password, secondary_hash, 256, 3072, 8, 1, ( error, progress, key ) => {
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
                } );

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
                let dc_lock_btn = $( '#dc-lock-btn' );

                /* Update the icon and toggle. */
                if ( !_configFile.encodeAll ) {
                    dc_lock_btn.attr( 'title', 'Disable Message Encryption' );
                    dc_lock_btn.html( Buffer.from( self._lockIcon, 'base64' ).toString( 'utf8' ) );
                    _configFile.encodeAll = true;
                }
                else {
                    dc_lock_btn.attr( 'title', 'Enable Message Encryption' );
                    dc_lock_btn.html( Buffer.from( self._unlockIcon, 'base64' ).toString( 'utf8' ) );
                    _configFile.encodeAll = false;
                }

                /* Set the button class. */
                $( '.dc-svg' ).attr( 'class', 'dc-svg' );

                /* Save config. */
                self._saveConfig();
            };
        }

        /**
         * @private
         * @desc Sets the active tab index in the settings menu.
         * @param {int} index The index ( 0-1 ) of the page to activate.
         * @example
         * setActiveTab( 1 );
         */
        static _setActiveSettingsTab( index ) {
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
         * @param {UpdateCallback} on_update_callback
         * @returns {boolean}
         * @example
         * _checkForUpdate( ( file_data, short_hash, new_version, full_changelog, validated ) => {
     *      console.log( `New Update Available: #${short_hash} - v${new_version}` );
     *      console.log( `Signature is: ${validated ? valid' : 'invalid'}!` );
     *      console.log( `Changelog:\n${full_changelog}` );
     * } );
         */
        static _checkForUpdate( on_update_callback ) {
            /* Update URL and request method. */
            const base_url = 'https://gitlab.com/leogx9r/discordCrypt/raw/master';
            const update_url = `${base_url}/build/${_discordCrypt._getPluginName()}`;
            const signing_key_url = `${base_url}/build/signing-key.pub`;
            const changelog_url = `${base_url}/src/CHANGELOG`;
            const signature_url = `${update_url}.sig`;

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
                            _discordCrypt.log( `Error while fetching update: ${errorString}`, 'error' );
                            break;
                        }

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
                        return false;
                    }

                    /* Read the current hash of the plugin and compare them.. */
                    let currentHash = _discordCrypt.sha256( localFile.replace( '\r', '' ) );
                    let hash = _discordCrypt.sha256( data.replace( '\r', '' ) );
                    let shortHash = Buffer.from( hash, 'base64' )
                        .toString( 'hex' )
                        .slice( 0, 8 );

                    /* If the hash equals the retrieved one, no update is needed. */
                    if ( hash === currentHash ) {
                        _discordCrypt.log( `No Update Needed - #${shortHash}` );
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
                        _discordCrypt.log( 'Failed to locate the version number in the update ...', 'warn' );
                    }

                    /* Basically the finally step - resolve the changelog & call the callback function. */
                    let tryResolveChangelog = ( valid_signature ) => {
                        /* Now get the changelog. */
                        try {
                            /* Fetch the changelog from the URL. */
                            _discordCrypt.__getRequest(
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
                            _discordCrypt.log( 'Error fetching the changelog.', 'warn' );

                            /* Perform the callback without a changelog. */
                            on_update_callback( data, shortHash, version_number, '', valid_signature );
                        }
                    };

                    /* Try validating the signature. */
                    try {
                        /* Fetch the signing key. */
                        _discordCrypt.__getRequest( signing_key_url, ( statusCode, errorString, signing_key ) => {
                            /* Fetch the detached signature. */
                            _discordCrypt.__getRequest( signature_url, ( statusCode, errorString, detached_sig ) => {
                                /* Validate the signature then continue. */
                                let r = _discordCrypt.__validatePGPSignature( data, detached_sig, signing_key );

                                /* This returns a Promise if valid or false if invalid. */
                                if( r )
                                    r.then( ( valid_signature ) => tryResolveChangelog( valid_signature ) );
                                else
                                    tryResolveChangelog( false );
                            } );
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

                    _discordCrypt.log( 'Cannot find React module.', 'warn' );
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
         * @experimental
         * @private
         * @desc Dumps all function callback handlers with their names, IDs and function prototypes. [ Debug Function ]
         * @param {boolean} [dump_actions] Whether to dump action handlers.
         * @returns {Array} Returns an array of all IDs and identifier callbacks.
         */
        static _dumpWebpackModuleCallbacks( dump_actions = true ) {
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
            let finder = _discordCrypt._getWebpackModuleSearcher().findByDispatchToken;

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
         * @desc Returns the React modules loaded natively in Discord.
         * @param {CachedModules} cached_modules Cached module parameter for locating standard modules.
         * @returns {ReactModules}
         */
        static _getReactModules( cached_modules ) {
            const blacklisted_channel_props = [
                '@me',
                'activity'
            ];

            if ( cached_modules ) {
                let channelProps = null;

                if( blacklisted_channel_props.indexOf( _discordCrypt._getChannelId() ) === -1 ) {
                    let elementOwner = _discordCrypt._getElementReactOwner( $( 'form' )[ 0 ] );

                    if( elementOwner[ 'props' ] && elementOwner.props[ 'channel' ] )
                        channelProps = elementOwner.props.channel;
                }

                return {
                    ChannelProps: channelProps,
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
            cached_modules.MessageController._deleteMessage( channel_id, message_id );
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
        static _dispatchMessage(
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
            const React = _discordCrypt._getReactModules( cached_modules );

            /* Parse the message content to the required format if applicable.. */
            if ( typeof message_content === 'string' && message_content.length ) {
                /* Sanity check. */
                if ( React.MessageParser === null ) {
                    _discordCrypt.log( 'Could not locate the MessageParser module!', 'error' );
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
            let _channel = channel_id !== undefined ? channel_id : _discordCrypt._getChannelId();

            /* Sanity check. */
            if ( React.MessageQueue === null ) {
                _discordCrypt.log( 'Could not locate the MessageQueue module!', 'error' );
                return;
            }

            /* Sanity check. */
            if ( React.MessageController === null ) {
                _discordCrypt.log( 'Could not locate the MessageController module!', 'error' );
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
                        _discordCrypt.log( `Error sending message: ${r.status}`, 'error' );

                        /* Sanity check. */
                        if ( React.MessageDispatcher === null || React.MessageActionTypes === null ) {
                            _discordCrypt.log( 'Could not locate the MessageDispatcher module!', 'error' );
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
                                    icon_url:
                                        'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/images/encode-logo.png',
                                    url: 'https://discord.me/_discordCrypt'
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
         * @desc Hooks a dispatcher from Discord's internals.
         * @author samogot
         * @param {object} dispatcher The action dispatcher containing an array of _actionHandlers.
         * @param {string} method_name The name of the method to hook.
         * @param {string} options The type of hook to apply. [ 'before', 'after', 'instead', 'revert' ]
         * @param {boolean} [options.once=false] Set to `true` if you want to automatically unhook
         *      method after first call.
         * @param {boolean} [options.silent=false] Set to `true` if you want to suppress log messages about patching and
         *      unhooking. Useful to avoid clogging the console in case of frequent conditional hooking/unhooking, for
         *      example from another monkeyPatch callback.
         * @return {function} Returns the function used to cancel the hook.
         */
        static _hookDispatcher( dispatcher, method_name, options ) {
            const { before, after, instead, once = false, silent = false } = options;
            const origMethod = dispatcher._actionHandlers[ method_name ];

            const cancel = () => {
                if ( !silent )
                    _discordCrypt.log( `Unhooking "${method_name}" ...` );
                dispatcher[ method_name ] = origMethod;
            };

            // eslint-disable-next-line consistent-return
            const suppressErrors = ( method, description ) => ( ... params ) => {
                try {
                    return method( ... params );
                }
                catch ( e ) {
                    _discordCrypt.log( `Error occurred in ${description}`, 'error' )
                }
            };

            if ( !dispatcher._actionHandlers[ method_name ].__hooked ) {
                if ( !silent )
                    _discordCrypt.log( `Hooking "${method_name}" ...` );

                dispatcher._actionHandlers[ method_name ] = function () {
                    /**
                     * @interface
                     * @name PatchData
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
                    'Please enter a password meeting these requirements.<br./>' +
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
                    input = Buffer.from( _discordCrypt.sha256( Buffer.concat( [ input, key ] ), true ), 'hex' );
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

                /* If the module can't be loaded, don't load this library. */
                if ( libInfo.requiresElectron ) {
                    try {
                        require( 'electron' );
                    }
                    catch ( e ) {
                        _discordCrypt.log( `Skipping loading of electron-required plugin: ${name} ...`, 'warn' );
                        continue;
                    }
                }

                /* Decompress the Base64 code. */
                let code = _discordCrypt.__zlibDecompress( libInfo.code );

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
                output[ 'fingerprint' ] = _discordCrypt.sha256( msg, true );

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
         * @desc Detects and extracts all formatted emojis in a message.
         * @param {string} message The message to extract all emojis from.
         * @param {boolean} as_html Whether to interpret anchor brackets as HTML.
         * @return {Array<EmojiDescriptor>} Returns an array of EmojiDescriptor objects.
         */
        static __extractEmojis( message, as_html = false ) {
            let _emojis = [], _matched;

            /* Execute the regex for finding emojis on the message. */
            let emoji_expr = new RegExp(
                as_html ?
                    /((&lt;)(:(?![\n])[-\w]+:)([0-9]{14,22})(&gt;))/gm :
                    /((<)(:(?![\n])[-\w]+:)([0-9]{14,22})(>))/gm
            );

            /* Iterate over each matched emoji. */
            while ( ( _matched = emoji_expr.exec( message ) ) ) {
                /* Insert the emoji's snowflake and name. */
                _emojis.push( {
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
                let _extracted = _discordCrypt.__extractCodeBlocks( message );

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
                let _extracted = _discordCrypt.__extractUrls( message );

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
                    message = message
                        .join( `${join}<a target="_blank" href="${_extracted[ i ]}">${_extracted[ i ]}</a>` );
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
         * @desc Extracts emojis from a message and formats them as IMG embeds.
         *      Basically, all emojis are formatted as follows:
         *          <:##EMOJI NAME##:##SNOWFLAKE##>
         *
         *      This translates to a valid URI always:
         *          https://cdn.discordapp.com/emojis/##SNOWFLAKE##.png
         *
         *      This means it's a simple matter of extracting these from a message and building an image embed.
         *          <img src="##URI##" class="emoji da-emoji jumboable da-jumboable" alt=":#EMOJI NAME##:">
         * @param {string} message The message to format.
         * @param {string} emoji_class The class used for constructing the emoji image.
         * @return {EmojiInfo} Returns whether the message contains Emojis and the formatted HTML.
         */
        static __buildEmojiMessage( message, emoji_class ) {
            /* Get all emojis in the message. */
            let emojis = _discordCrypt.__extractEmojis( message, true );

            /* Return the default if no emojis are defined. */
            if( !emojis.length ) {
                return {
                    emoji: false,
                    html: message
                }
            }

            /* Loop over every emoji and format them in the message.. */
            for( let i = 0; i < emojis.length; i++ ) {
                /* Get the URI for this. */
                let URI = `https://cdn.discordapp.com/emojis/${emojis[ i ].snowflake}.png`;

                /* Replace the message with a link. */
                message = message
                    .split( emojis[ i ].formatted )
                    .join( `<img src="${URI}" class="${emoji_class}" alt=":${emojis[ i ].name}:">` );
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
                _discordCrypt.pbkdf2_sha160(
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
                    hash = _discordCrypt.whirlpool64;
                    break;
                case 16:
                    hash = _discordCrypt.sha512_128;
                    break;
                case 20:
                    hash = _discordCrypt.sha160;
                    break;
                case 24:
                    hash = _discordCrypt.whirlpool192;
                    break;
                case 32:
                    hash = _discordCrypt.sha256;
                    break;
                case 64:
                    hash = use_whirlpool !== undefined ? _discordCrypt.sha512 : _discordCrypt.whirlpool;
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
         * @desc Retrieves Base64 charset as an Array Object.
         * @returns {Array} Returns an array of all 64 characters used in Base64 + encoding characters.
         */
        static __getBase64() {
            return Array.from( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" );
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
                    _salt = Buffer.from( _discordCrypt.whirlpool64( _salt, true ), 'hex' );
            }
            else {
                /* Generate a random salt to derive the key and IV. */
                _salt = crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            _derived = _discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
            _derived = _discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
                    return _discordCrypt.blowfish512_encrypt( message, key, mode, pad );
                case 1:
                    return _discordCrypt.aes256_encrypt( message, key, mode, pad );
                case 2:
                    return _discordCrypt.camellia256_encrypt( message, key, mode, pad );
                case 3:
                    return _discordCrypt.idea128_encrypt( message, key, mode, pad );
                case 4:
                    return _discordCrypt.tripledes192_encrypt( message, key, mode, pad );
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
                msg = _discordCrypt.blowfish512_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 5 && cipher_index <= 9 )
                msg = _discordCrypt.aes256_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index - 5, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 10 && cipher_index <= 14 )
                msg = _discordCrypt.camellia256_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index - 10, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 15 && cipher_index <= 19 )
                msg = _discordCrypt.idea128_encrypt(
                    handleEncodeSegment( message, primary_key, cipher_index - 15, mode, pad ),
                    secondary_key,
                    mode,
                    pad,
                    true,
                    false
                );
            else if ( cipher_index >= 20 && cipher_index <= 24 )
                msg = _discordCrypt.tripledes192_encrypt(
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
                    return _discordCrypt.blowfish512_decrypt( message, key, mode, pad, output_format, is_message_hex );
                case 1:
                    return _discordCrypt.aes256_decrypt( message, key, mode, pad, output_format, is_message_hex );
                case 2:
                    return _discordCrypt.camellia256_decrypt( message, key, mode, pad, output_format, is_message_hex );
                case 3:
                    return _discordCrypt.idea128_decrypt( message, key, mode, pad, output_format, is_message_hex );
                case 4:
                    return _discordCrypt.tripledes192_decrypt( message, key, mode, pad, output_format, is_message_hex );
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
                        _discordCrypt.blowfish512_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 5 && cipher_index <= 9 )
                    return handleDecodeSegment(
                        _discordCrypt.aes256_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index - 5,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 10 && cipher_index <= 14 )
                    return handleDecodeSegment(
                        _discordCrypt.camellia256_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index - 10,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 15 && cipher_index <= 19 )
                    return handleDecodeSegment(
                        _discordCrypt.idea128_decrypt( message, secondary_key, mode, pad, 'base64' ),
                        primary_key,
                        cipher_index - 15,
                        mode,
                        pad,
                        'utf8',
                        false
                    );
                else if ( cipher_index >= 20 && cipher_index <= 24 )
                    return handleDecodeSegment(
                        _discordCrypt.tripledes192_decrypt( message, secondary_key, mode, pad, 'base64' ),
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
        static whirlpool64( message, to_hex ) {
            return Buffer.from( _discordCrypt.whirlpool( message, true ), 'hex' )
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
            return Buffer.from( _discordCrypt.sha512( message, true ), 'hex' )
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
            return Buffer.from( _discordCrypt.sha512( message, true ), 'hex' )
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
            return _discordCrypt.__createHash( message, 'sha1', to_hex );
        }

        /**
         * @public
         * @desc Returns an SHA-256 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static sha256( message, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha256', to_hex );
        }

        /**
         * @public
         * @desc Returns an SHA-512 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static sha512( message, to_hex ) {
            return _discordCrypt.__createHash( message, 'sha512', to_hex );
        }

        /**
         * @public
         * @desc Returns a Whirlpool-512 digest of the message.
         * @param {Buffer|Array|string} message The input message to hash.
         * @param {boolean} to_hex Whether to convert the result to hex or Base64.
         * @returns {string} Returns the hex or Base64 encoded result.
         */
        static whirlpool( message, to_hex ) {
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
        static hmac_sha256( message, secret, to_hex ) {
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
        static hmac_sha512( message, secret, to_hex ) {
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
        static hmac_whirlpool( message, secret, to_hex ) {
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
        static pbkdf2_sha512(
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
                    _salt = Buffer.from( _discordCrypt.whirlpool64( _salt, true ), 'hex' );
            }
            else {
                /* Generate a random salt to derive the key and IV. */
                _salt = crypto.randomBytes( 8 );
            }

            /* Derive the key length and IV length. */
            _derived = _discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
            _derived = _discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
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
    Object.freeze( _discordCrypt.prototype );

    /* Freeze the class definition. */
    Object.freeze( _discordCrypt );

    return _discordCrypt;
} )();

/* Also freeze the method. */
Object.freeze( discordCrypt );

/* Required for code coverage reports. */
module.exports = { discordCrypt };
