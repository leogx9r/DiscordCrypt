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

/* Main plugin prototype. */
class discordCrypt {
    /* ============================================================== */

    /* Standard BetterDiscord Plugin Info. */
    getName() {
        return 'DiscordCrypt';
    }

    getDescription() {
        return 'Provides secure messaging for Discord using various cryptography standards.';
    }

    /* Version & Author. */
    getAuthor() {
        return 'Leonardo Gates';
    }

    getVersion() {
        return '1.0.5';
    }

    /* ============================================================== */

    /* Default Constructor */
    constructor() {

        /* ============================================ */

        /**
         * Discord class names that changes ever so often because they're douches.
         * These will usually be the culprit if the plugin breaks.
         */

        /* Used to scan each message. */
        this.messageMarkupClass = '.markup';
        /* Used to inject the toolbar. */
        this.searchUiClass = '.search .search-bar';
        /* Used to hook messages being sent. */
        this.channelTextAreaClass = '.content textarea';

        /* ============================================ */

        /* Defines what an encrypted message starts with. Must be 4x UTF-16 bytes. */
        this.encodedMessageHeader = "㑳㑵㑷㑼";

        /* Defines what a public key message starts with. Must be 4x UTF-16 bytes. */
        this.encodedKeyHeader = "㑼㑷㑵㑳";

        /* Defines what the header of an encrypted message says. */
        this.messageHeader = '-----ENCRYPTED MESSAGE-----';

        /* Master database password. This uses 256 bits. An AES-256 bit key. */
        this.masterPassword = new Buffer( 32 );

        /* Scanning interval handler. */
        this.scanInterval = undefined;

        /* Configuration file. */
        this.configFile = null;

        /* Symmetric encryption modes. */
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

        /* Symmetric block modes of operation. */
        this.encryptBlockModes = [
            'CBC', /* Cipher Block-Chaining */
            'CFB', /* Cipher Feedback Mode */
            'OFB', /* Output Feedback Mode */
        ];

        /* Padding modes for block ciphers. */
        this.paddingModes = [
            'PKC7', /* PKCS #7 */
            'ANS2', /* ANSI X.923 */
            'ISO1', /* ISO-10126 */
            'ISO9', /* ISO-97972 */
            'ZR0', /* Zero-Padding */
        ];

        /* Defines the CSS for the application overlay. */
        this.appCss = `
            .dc-overlay {
                position: fixed;
                font-family: monospace;
                display: none;
                width: 100%;
                height: 100%;
                left: 0;
                right: 0;
                top: 0;
                bottom: 0;
                z-index: 50000;
                cursor: default;
                background: rgba(0, 0, 0, 0.85) !important;
            }
            .dc-password-field {
                width: 95%;
                margin: 10px;
                color: #ffffff;
                height: 10px;
                padding: 5px;
                background-color: #000000;
                border: 2px solid #3a71c1;
            }
            .dc-overlay-centerfield {
                position: absolute;
                top: 35%;
                left: 50%;
                font-size: 20px;
                color: #ffffff;
                padding: 16px;
                border-radius: 20px;
                background: rgba(0, 0, 0, 0.7);
                transform: translate(-50%, 50%);
            }
            .dc-overlay-main {
                margin: 20px;
                overflow: hidden;
                position: absolute;
                left: 5%; right: 5%;
                top: 5%; bottom: 5%;
                width: 90%; height: 90%;
                border: 3px solid #3f3f3f;
            }
            .dc-textarea {
                font-family: monospace;
                font-size: 12px;
                color: #ffffff;
                background: #000;
                overflow: auto;
                padding: 5px;
                resize: none;
                height: 100%;
                width: 100%;
                margin: 2px;           
            }
            .dc-update-field {
                font-size: 14px;
                margin: 10px;
            }
            ul.dc-list {
                margin: 10px;
                padding: 5px;
                list-style-type: circle;
            }
            ul.dc-list > li { padding: 5px; }
            ul.dc-list-red { color: #ff0000; }
            .dc-overlay-main textarea {
                background: transparent !important;
                cursor: default;
                font-size: 12px;
                padding: 5px;
                margin-top: 10px;
                border-radius: 2px;
                resize: none;
                color: #8e8e8e;
                width: 70%;
                overflow-y: hidden;
                user-select: none;
            }
            .dc-overlay-main select {
                background-color: transparent;
                border-radius: 3px;
                font-size: 12px;
                color: #fff;
            }
            .dc-overlay-main select:hover {
                background-color: #000 !important;
                color: #fff;
            }
            .dc-input-field {
                font-family: monospace !important;
                background: #000 !important;
                color: #fff !important;
                border-radius: 3px;
                font-size: 12px;
                width: 40%;
                margin-bottom: 10px;
                margin-top: -5px;
                margin-left: 10%;
            }
            .dc-input-label {
                font-family: monospace !important;
                color: #708090;
                min-width: 20%;
            }
            .dc-ruler-align {
                display: flex;
                margin: 10px;
            }
            .dc-code-block {
                font-family: monospace !important;
                font-size: 0.875rem;
                line-height: 1rem;
                
                overflow-x: visible;
                text-indent: 0;
                
                background: rgba(0,0,0,0.42)!important;
                color: hsla(0,0%,100%,0.7)!important;
                padding: 6px!important;
                
                position: relative;            
            }
            .dc-overlay-main .tab {
                overflow: hidden;
                background-color: rgba(0, 0, 0, .9) !important;
                border: 1px dotted #ffffff;
                padding: 2px;
            }
            .dc-overlay-main .tab button {
                color: #008000;
                background-color: inherit;
                cursor: pointer;
                padding: 14px 14px;
                font-size: 14px;
                transition: 0.5s;
                font-family: monospace;
                border-radius: 3px;
                margin: 3px;
            }
            .dc-overlay-main .tab button:hover {
                background-color: #515c6b;
            }
            .dc-overlay-main .tab button.active {
                background-color: #1f1f2b;
            }
            .dc-overlay-main .tab-content {
                display: none;
                height: 95%;
                color: #9298a2;
                overflow: auto;
                padding: 10px 25px 5px;
                animation: fadeEffect 1s;
                background: rgba(0, 0, 0, 0.7) !important;
            }
            .dc-main-overlay .tab-content .dc-hint {
                margin: 14px;
                padding-left: 5px;
                font-size: 12px;
                color: #f08080;
            }
            .dc-svg { 
                color: #fff; opacity: .6;
                margin: 0 4px;
                cursor: pointer;
                width: 24px;
                height: 24px;
            }
            .dc-svg:hover {
                color: #fff; opacity: .8;
            }
            .dc-button{
                margin-right: 5px;
                margin-left: 5px;
                background-color: #7289da;
                color: #fff;
                align-items: center;
                border-radius: 3px;
                box-sizing: border-box;
                display: flex;
                font-size: 14px;
                width: auto;
                height: 32px;
                min-height: 32px;
                min-width: 60px;
                font-weight: 500;
                justify-content: center;
                line-height: 16px;
                padding: 2px 16px;
                position: relative;
                user-select: none;  
            }
            .dc-button:hover{ background-color: #677bc4 !important; }
            .dc-button:active{ background-color: #5b6eae !important; }
            .dc-button-inverse{
                color: #f04747;
                background: transparent !important;
                border: 1px solid rgba(240,71,71,.3);
                transition: color .17s ease,background-color .17s ease,border-color .17s ease;
            }
            .dc-button-inverse:hover{
                border-color: rgba(240,71,71,.6);
                background: transparent !important;
            }
            .dc-button-inverse:active{ background-color: rgba(240,71,71,.1); }
            .stat-levels {
                box-shadow: inset 0 0 25px rgba(0,0,0,.5);
                margin: 5px auto 0 auto;
                height: 20px;
                padding: 15px;
                border: 1px solid #494a4e;
                border-radius: 10px;
                background: linear-gradient(#444549 0%, #343539 100%);
            }
            .stat-bar {
                background-color: #2a2b2f;
                box-shadow: inset 0 5px 15px rgba(0,0,0,.6);
                height: 15px;
                overflow: hidden;
                padding: 3px;
                border-radius: 3px;
                margin-bottom: 10px;
                margin-top: 10px;
                margin-left: 0;
            }
            .stat-bar-rating {
                border-radius: 4px;
                float: left;
                height: 100%;
                font-size: 12px;
                color: #ffffff;
                text-align: center;
                text-indent: -9999px;
                background-color: #3a71c1;
                box-shadow: inset 0 -1px 0 rgba(0, 0, 0, 0.15);
            }
            .stat-bar-rating { @include stat-bar(#cf3a02, #ff4500, top, bottom); }
            `;

        this.toolbarHtml =
            `
            <button type="button" id="dc-file-btn" style="background-color: transparent;" title="Upload Encrypted File">
                <svg class="dc-svg" width="24" height="24" viewBox="0 0 1792 1792" fill="lightgrey">
                    <path d="M768 384v-128h-128v128h128zm128 128v-128h-128v128h128zm-128 
                        128v-128h-128v128h128zm128 128v-128h-128v128h128zm700-388q28 28 48 
                        76t20 88v1152q0 40-28 68t-68 28h-1344q-40 0-68-28t-28-68v-1600q0-40 28-68t68-28h896q40 
                        0 88 20t76 48zm-444-244v376h376q-10-29-22-41l-313-313q-12-12-41-22zm384 1528v-1024h-416q-40 
                        0-68-28t-28-68v-416h-128v128h-128v-128h-512v1536h1280zm-627-721l107 349q8 27 8 52 0 83-72.5 
                        137.5t-183.5 54.5-183.5-54.5-72.5-137.5q0-25 8-52 21-63 120-396v-128h128v128h79q22 0 39 
                        13t23 34zm-141 465q53 0 90.5-19t37.5-45-37.5-45-90.5-19-90.5 19-37.5 45 37.5 45 90.5 19z">
                    </path>
                </svg>           
            </button>
            <button type="button" id="dc-settings-btn" style="background-color: transparent;" title="DiscordCrypt Settings">
                <svg class="dc-svg" enable-background="new 0 0 32 32" version="1.1" viewBox="0 0 32 32" 
                width="20px" height="20px" xml:space="preserve">
                    <g>
                        <path fill="lightgrey" d="M28,10H18v2h10V10z M14,10H4v10h10V10z M32,0H0v28h15.518c1.614,2.411,4.361,3.999,7.482,4c4.971-0.002,8.998-4.029,9-9   
                        c0-0.362-0.027-0.718-0.069-1.069L32,22V0z M10,2h12v2H10V2z M6,2h2v2H6V2z M2,2h2v2H2V2z M23,29.883   
                        c-3.801-0.009-6.876-3.084-6.885-6.883c0.009-3.801,3.084-6.876,6.885-6.885c3.799,0.009,6.874,3.084,6.883,6.885   
                        C29.874,26.799,26.799,29.874,23,29.883z M29.999,17.348c-0.57-0.706-1.243-1.324-1.999-1.83V14h-4.99c-0.003,0-0.007,0-0.01,0   
                        s-0.007,0-0.01,0H18v1.516c-2.412,1.614-4,4.361-4,7.483c0,1.054,0.19,2.061,0.523,3H2V6h27.999V17.348z M30,4h-4V2h4V4z"/>
                        <path fill="lightgrey" d="M28,24v-2.001h-1.663c-0.063-0.212-0.145-0.413-0.245-0.606l1.187-1.187l-1.416-1.415l-1.165,1.166   
                        c-0.22-0.123-0.452-0.221-0.697-0.294V18h-2v1.662c-0.229,0.068-0.446,0.158-0.652,0.27l-1.141-1.14l-1.415,1.415l1.14,1.14   
                        c-0.112,0.207-0.202,0.424-0.271,0.653H18v2h1.662c0.073,0.246,0.172,0.479,0.295,0.698l-1.165,1.163l1.413,1.416l1.188-1.187   
                        c0.192,0.101,0.394,0.182,0.605,0.245V28H24v-1.665c0.229-0.068,0.445-0.158,0.651-0.27l1.212,1.212l1.414-1.416l-1.212-1.21   
                        c0.111-0.206,0.201-0.423,0.27-0.651H28z M22.999,24.499c-0.829-0.002-1.498-0.671-1.501-1.5c0.003-0.829,0.672-1.498,1.501-1.501   
                        c0.829,0.003,1.498,0.672,1.5,1.501C24.497,23.828,23.828,24.497,22.999,24.499z"/>
                    </g>
                </svg>
            </button>
            <button type="button" id="dc-lock-btn" style="background-color: transparent;"/>
            <button type="button" id="dc-passwd-btn" style="background-color: transparent;" title="Password Settings">
                <svg class="dc-svg" version="1.1" viewBox="0 0 32 32" width="20px" height="20px">
                    <g fill="none" fill-rule="evenodd" stroke="none" stroke-width="1">
                        <g fill="lightgrey">
                            <path d="M13.008518,22 L11.508518,23.5 L11.508518,23.5 L14.008518,26 L11.008518,29 L8.50851798,26.5 L6.63305475,28.3754632 C5.79169774,29.2168202 
                            4.42905085,29.2205817 3.5909158,28.3824466 L3.62607133,28.4176022 C2.78924,27.5807709 2.79106286,26.2174551 3.63305475,25.3754632 L15.7904495,13.2180685
                             C15.2908061,12.2545997 15.008518,11.1602658 15.008518,10 C15.008518,6.13400656 18.1425245,3 22.008518,3 C25.8745114,3 
                             29.008518,6.13400656 29.008518,10 C29.008518,13.8659934 25.8745114,17 22.008518,17 C20.8482521,17 19.7539183,16.7177118 18.7904495,16.2180685 
                             L18.7904495,16.2180685 L16.008518,19 L18.008518,21 L15.008518,24 L13.008518,22 L13.008518,22 L13.008518,22 Z M22.008518,14 C24.2176571,14 
                             26.008518,12.2091391 26.008518,10 C26.008518,7.79086089 24.2176571,6 22.008518,6 C19.7993789,6 18.008518,7.79086089 18.008518,10 C18.008518,12.2091391 
                             19.7993789,14 22.008518,14 L22.008518,14 Z" id="key"/>
                        </g>
                    </g>
                </svg>
            </button>
            <button type="button" id="dc-exchange-btn" style="background-color: transparent;" title="Key Exchange Menu">
                <svg class="dc-svg" version="1.1" viewBox="0 0 78 78" width="20px" height="20px">
                    <path d="M72,4.5H6c-3.299,0-6,2.699-6,6V55.5c0,3.301,2.701,6,6,6h66c3.301,0,6-2.699,6-6V10.5  C78,7.2,75.301,4.5,72,4.5z M72,50.5H6V10.5h66V50.5z 
                    M52.5,67.5h-27c-1.66,0-3,1.341-3,3v3h33v-3C55.5,68.84,54.16,67.5,52.5,67.5z   M26.991,36.5H36v-12h-9.009v-6.729L15.264,30.5l11.728,12.728V36.5z 
                    M50.836,43.228L62.563,30.5L50.836,17.771V24.5h-9.009v12  h9.009V43.228z" style="fill:#d3d3d3;"/>
                </svg>
            </button>
            <button type="button" id="dc-quick-exchange-btn" style="background-color: transparent;" title="Generate & Send New Public Key">
                <svg class="dc-svg iconActive-AKd_jq icon-1R19_H iconMargin-2YXk4F" x="0px" y="0px" viewBox="0 0 58 58">
                    <path style="fill:#d3d3d3;" d="M27.767,26.73c-2.428-2.291-3.766-5.392-3.766-8.729c0-6.617,5.383-12,12-12s12,5.383,12,12  
                    c0,3.288-1.372,6.469-3.765,8.728l-1.373-1.455c2.023-1.909,3.138-4.492,3.138-7.272c0-5.514-4.486-10-10-10s-10,4.486-10,10  
                    c0,2.781,1.114,5.365,3.139,7.274L27.767,26.73z"/>
                    <path style="fill:#d3d3d3;" d="M56.428,38.815c-0.937-0.695-2.188-0.896-3.435-0.55l-15.29,4.227  
                    C37.891,42.028,38,41.522,38,40.991c0-2.2-1.794-3.991-3.999-3.991h-9.377c-0.667-1-2.363-4-4.623-4H16v-0.999  
                    C16,30.347,14.654,29,13,29H9c-1.654,0-3,1.347-3,3v17C6,50.655,7.346,52,9,52h4c1.654,0,3-1.345,3-2.999v-0.753l12.14,8.201  
                    c1.524,1.031,3.297,1.55,5.075,1.55c1.641,0,3.286-0.441,4.742-1.33l18.172-11.101C57.283,44.864,58,43.587,58,42.233v-0.312  
                    C58,40.688,57.427,39.556,56.428,38.815z M14,49C14,49.553,13.552,50,13,50h-1v-4h-2v4H9c-0.552,0-1-0.447-1-0.999v-17  
                    C8,31.449,8.448,31,9,31h4c0.552,0,1,0.449,1,1V49z M56,42.233c0,0.66-0.35,1.284-0.913,1.628L36.915,54.962  
                    c-2.367,1.443-5.37,1.376-7.655-0.17L16,45.833V35h4c1.06,0,2.469,2.034,3.088,3.409L23.354,39h10.646  
                    C35.104,39,36,39.892,36,40.988C36,42.098,35.104,43,34,43H29h-5v2h5h5h2l17.525-4.807c0.637-0.18,1.278-0.094,1.71,0.228  
                    C55.722,40.781,56,41.328,56,41.922V42.233z"/>
                    <path style="fill:#d3d3d3;" d="M33,25.394v6.607C33,33.655,34.347,35,36,35H38h1h4v-2h-4v-2h2v-2h-2v-3.577  
                    c3.02-1.186,5-4.079,5-7.422c0-2.398-1.063-4.649-2.915-6.177c-1.85-1.524-4.283-2.134-6.683-1.668  
                    c-3.155,0.614-5.671,3.153-6.261,6.318C27.39,20.523,29.933,24.041,33,25.394z M30.108,16.84c0.44-2.364,2.319-4.262,4.677-4.721  
                    c1.802-0.356,3.639,0.104,5.028,1.249S42,16.202,42,18c0,2.702-1.719,5.011-4.276,5.745L37,23.954V33h-0.999  
                    C35.449,33,35,32.553,35,32v-8.02l-0.689-0.225C31.822,22.943,29.509,20.067,30.108,16.84z"/>
                    <path d="M36,22c2.206,0,4-1.794,4-4s-1.794-4-4-4s-4,1.794-4,4S33.795,22,36,22z   M36,16c1.103,0,2,0.897,2,2s-0.897,2-2,2s-2-0.897-2-2S34.898,16,36,16z"/>
                    <circle style="fill:#d3d3d3;" cx="36" cy="18" r="3"/>
                </svg>
            </button>
            `;

        this.masterPasswordHtml =
            `
            <div id="dc-master-overlay" class="dc-overlay">
                <div id="dc-overlay-centerfield" class="dc-overlay-centerfield" style="top: 30%">
                    <h2 style="color:#ff0000;" id="dc-header-master-msg"></h2>
                    <br/><br/>
                    
                    <span id="dc-prompt-master-msg"></span><br/>
                    <input type="password" class="dc-password-field" id="dc-db-password"/>
                    <br/>
                    
                    <div class="stat stat-bar">
                        <span id = "dc-master-status" class="stat-bar-rating" style="width: 0;"/>
                    </div>

                    <div class="dc-ruler-align">
                        <button class="dc-button" style="width:100%;" id="dc-unlock-database-btn"/>
                    </div>
                    
                    <div class="dc-ruler-align">
                        <button class="dc-button dc-button-inverse" style="width:100%;" id="dc-cancel-btn">Cancel</button>
                    </div>
                </div>
            </div>
            `;

        this.settingsMenuHtml =
            `
            <div id="dc-overlay" class="dc-overlay">
                <div id="dc-overlay-upload" class="dc-overlay-centerfield" style="display:none; top: 5%;">
                    <div class="dc-ruler-align">
                        <input type="text" class="dc-input-field" id="dc-file-path" 
                            style="width: 100%;padding: 2px;margin-left: 4px;" readonly/>
                        <button class="dc-button dc-button-inverse" type="button" id="dc-select-file-path-btn" 
                            style="top: -8px;"> . . .</button>
                    </div>
                    
                    <textarea class="dc-textarea" rows="20" cols="128" id="dc-file-message-textarea" 
                        placeholder="Enter any addition text to send with your message ..." maxlength="1100"/>
                        
                    <div class="dc-ruler-align" style="font-size:14px; padding-bottom:10px;">
                        <input id="dc-file-deletion-checkbox" class="ui-switch-checkbox" type="checkbox">
                            <span style="margin-top: 5px;">Send Deletion Link</span>
                    </div>
                    <div class="dc-ruler-align" style="font-size:14px; padding-bottom:10px;">
                        <input id="dc-file-name-random-checkbox" class="ui-switch-checkbox" type="checkbox" checked>
                        <span style="margin-top: 5px;">Randomize File Name</span>
                    </div>
                    
                    <div class="stat stat-bar">
                        <span id = "dc-file-upload-status" class="stat-bar-rating" style="width: 0;"/>
                    </div>

                    <div class="dc-ruler-align">
                        <button class="dc-button" style="width:100%;" id="dc-file-upload-btn">Upload</button>
                    </div>
                    
                    <div class="dc-ruler-align">
                        <button class="dc-button dc-button-inverse" style="width:100%;" id="dc-file-cancel-btn">
                        Close</button>
                    </div>
                </div>
                <div id="dc-overlay-password" class="dc-overlay-centerfield" style="display:none;">
                    <span>Primary Password:</span>
                    <input type="password" class="dc-password-field" id="dc-password-primary" placeholder="..."/><br/>
                    
                    <span>Secondary Password:</span>
                    <input type="password" class="dc-password-field" id="dc-password-secondary" placeholder="..."/><br/>
                    
                    <div class="dc-ruler-align">
                        <button class="dc-button" id="dc-save-pwd">Update Passwords</button>
                        <button class="dc-button dc-button-inverse" id="dc-reset-pwd">Reset Passwords</button>
                        <button class="dc-button dc-button-inverse" id="dc-cancel-btn">Cancel</button>
                    </div>
                    
                    <button class="dc-button dc-button-inverse" style="width: 100%;" id="dc-cpy-pwds-btn">
                    Copy Current Passwords</button>
                </div>
                <div id="dc-update-overlay" class="dc-overlay-centerfield" 
                style="top: 5%;border: 1px solid;display: none">
                    <span>DiscordCrypt: Update Available</span>
                    <div class="dc-ruler-align">
                        <strong class="dc-hint dc-update-field" id="dc-new-version"/>
                    </div>
                    <div class="dc-ruler-align">
                        <strong class="dc-hint dc-update-field" id="dc-old-version"/>
                    </div>
                    <div class="dc-ruler-align">
                        <strong class="dc-hint dc-update-field">Changelog:</strong></div>
                    <div class="dc-ruler-align">
                        <textarea class="dc-textarea" rows="20" cols="128" id="dc-changelog" readonly/>
                    </div>
                    <br>
                    <div class="dc-ruler-align">
                        <button class="dc-button" id="dc-restart-now-btn" style="width: 50%;">Restart Now</button>
                        <button class="dc-button dc-button-inverse" id="dc-restart-later-btn" style="width: 50%;">
                        Restart Later</button>
                    </div>
                </div>
                <div id="dc-overlay-settings" class="dc-overlay-main" style="display: none;">
                    <div class="tab" id="dc-settings-tab">
                        <button class='dc-tab-link' id="dc-exit-settings-btn" style="float:right;">[ X ]</button>
                    </div>
                    <div class="tab-content" id="dc-settings" style="display: block;">
                        <p style="text-align: center;">
                            <b>DiscordCrypt Settings</b>
                        </p>
                        <br/><br/>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Primary Cipher:</div>
                            <select class="dc-input-field" id="dc-primary-cipher">
                                <option value="bf" selected>Blowfish ( 512-Bit )</option>
                                <option value="aes">AES ( 256-Bit )</option>
                                <option value="camel">Camellia ( 256-Bit )</option>
                                <option value="tdes">TripleDES ( 192-Bit )</option>
                                <option value="idea">IDEA ( 128-Bit )</option>
                            </select>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Secondary Cipher:</div>
                            <select class="dc-input-field" id="dc-secondary-cipher">
                                <option value="bf">Blowfish ( 512-Bit )</option>
                                <option value="aes">AES ( 256-Bit )</option>
                                <option value="camel">Camellia ( 256-Bit )</option>
                                <option value="idea">IDEA ( 256-Bit )</option>
                                <option value="tdes">TripleDES ( 192-Bit )</option>
                            </select>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Padding Mode:</div>
                            <select class="dc-input-field" id="dc-settings-padding-mode">
                                <option value="pkc7">PKCS #7</option>
                                <option value="asn2">ANSI X9.23</option>
                                <option value="iso1">ISO 10126</option>
                                <option value="iso9">ISO 97971</option>
                                <option value="zr0">Zero Padding</option>
                            </select>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Cipher Operation Mode:</div>
                            <select class="dc-input-field" id="dc-settings-cipher-mode">
                                <option value="cbc">Cipher Block Chaining</option>
                                <option value="cfb">Cipher Feedback Mode</option>
                                <option value="ofb">Output Feedback Mode</option>
                            </select>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Default Encryption Password:</div>
                            <input type="text" class="dc-input-field" id="dc-settings-default-pwd"/>                        
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Encryption Scanning Frequency:</div>
                            <input type="text" class="dc-input-field" id="dc-settings-scan-delay"/>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">Message Trigger:</div>
                            <input type="text" class="dc-input-field" id="dc-settings-encrypt-trigger"/>
                        </div>
                        
                        <div style="font-size: 9px;">
                            <div style="display: flex;">
                                <div style="width: 30%;"></div>
                                <p class="dc-hint">
                                The suffix at the end of a typed message to indicate whether to encrypt the text.</p>
                            </div>
                            <div style="display: flex;">
                                <div style="width: 30%;"></div>
                                <p class="dc-hint">Example: <u>This message will be encrypted.|ENC</u></p>
                            </div>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <div class="dc-input-label">New Master Database Password:</div>
                            <input type="text" class="dc-input-field" id="dc-master-password"/>
                        </div>
                        
                        <div class="dc-ruler-align">
                            <button id="dc-settings-save-btn" class="dc-button">Save & Apply</button>
                            <button id="dc-settings-reset-btn" class="dc-button dc-button-inverse">
                            Reset Settings</button>
                        </div>
                    </div>
                </div>
                <div id="dc-overlay-exchange" class="dc-overlay-main" style="display: none;">
                    <div class="tab" id="dc-exchange-tab">
                        <button class='dc-tab-link' id="dc-tab-info-btn">Info</button>
                        <button class='dc-tab-link' id="dc-tab-keygen-btn">Key Generation</button>
                        <button class='dc-tab-link' id="dc-tab-handshake-btn">Secret Computation</button>
                        <button class='dc-tab-link' id="dc-exit-exchange-btn" style="float:right;">[ X ]</button>
                    </div>
                    <div class="tab-content" id="dc-about-tab" style="display: block;">
                        <p style="text-align: center;">
                            <b>Key Exchanger</b>
                        </p>
                        <br/>
                        
                        <strong>What is this used for?</strong>
                        <ul class="dc-list">
                            <li>Simplifying the process or generating strong passwords for each user of DiscordCrypt 
                            requires a secure channel to exchange these keys.</li>
                            <li>Using this generator, you may create new keys using standard algorithms such as 
                            DH or ECDH for manual handshaking.</li>
                            <li>Follow the steps below and you can generate a password between channels or users 
                            while being able to publicly post the messages.</li>
                            <li>This generator uses secure hash algorithms ( SHA-256 and SHA-512 ) in tandem with 
                            the Scrypt KDF function to derive two keys.</li>
                        </ul>
                        <br/>
                        
                        <strong>How do I use this?</strong>
                        <ul class="dc-list">
                            <li>Generate a key pair using the specified algorithm and key size on the 
                            "Key Generation" tab.</li>
                            <li>Give your partner your public key by clicking the "Send Public Key" button.</li>
                            <li>Ask your partner to give you their public key using the same step above.</li>
                            <li>Copy your partner's public key and paste it in the "Secret Computation" tab and 
                            select "Compute Secret Keys".</li>
                            <li>Wait for <span style="text-decoration: underline;color: #ff0000;">BOTH</span> the primary and secondary 
                            keys to be generated.</li>
                            <li>A status bar is provided to easily tell you when both passwords 
                            have been generated.</li>
                            <li>Click the "Apply Generated Passwords" button to apply both passwords to 
                            the current user or channel.</li>
                        </ul>
                        
                        <strong>Algorithms Supported:</strong>
                        <ul class="dc-list">
                            <li>
                                <a title="Diffie–Hellman key exchange" 
                                href="https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange"
                                 target="_blank" rel="noopener">Diffie-Hellman ( DH )</a>
                            </li>
                            <li>
                                <a title="Elliptic curve Diffie–Hellman" 
                                href="https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman"
                                 target="_blank" rel="noopener">Elliptic Curve Diffie-Hellman ( ECDH )</a>
                            </li>
                        </ul>
                        
                        <span style="text-decoration: underline; color: #ff0000;">
                            <strong>DO NOT:</strong>
                        </span>
                        <ul class="dc-list dc-list-red">
                            <li>
                                <strong>Post your private key. If you do, generate a new one IMMEDIATELY.</strong>
                            </li>
                            <li>
                                <strong>Alter your public key or have your partner alter theirs in any way.</strong>
                            </li>
                            <li>
                                <strong>Insert a random public key.</strong>
                            </li>
                        </ul>
                    </div>
                    <div class="tab-content" id="dc-keygen-tab" style="display: block;">
                        <p style="text-align: center;">
                            <b style="font-size: large;">Secure Key Generation</b>
                        </p>
                        <br/>
                        
                        <strong>Exchange Algorithm:</strong>
                        <select id="dc-keygen-method">
                            <option value="dh" selected>Diffie-Hellman</option>
                            <option value="ecdh">Elliptic-Curve Diffie-Hellman</option>
                        </select>
                        <br/><br/>
                
                        <strong>Key Length ( Bits ):</strong>
                        <select id="dc-keygen-algorithm">
                            <option value="768">768</option>
                            <option value="1024">1024</option>
                            <option value="1536">1536</option>
                            <option value="2048">2048</option>
                            <option value="3072">3072</option>
                            <option value="4096">4096</option>
                            <option value="6144">6144</option>
                            <option value="8192" selected>8192</option>
                        </select>
                        <br/><br/>
                
                        <div class="dc-ruler-align">
                            <button id="dc-keygen-gen-btn" class="dc-button">Generate</button>
                            <button id="dc-keygen-clear-btn" class="dc-button dc-button-inverse">Clear</button>
                        </div>
                        <br/><br/><br/>
                
                        <strong>Private Key: ( <span style="text-decoration: underline; color: #ff0000;">KEEP SECRET</span> )</strong><br/>
                        <textarea id="dc-priv-key-ta" rows="8" cols="128" maxsize="8192"
                         unselectable="on" disabled readonly/>
                        <br/><br/>
                
                        <strong>Public Key:</strong><br/>
                        <textarea id="dc-pub-key-ta" rows="8" cols="128" maxsize="8192" 
                        unselectable="on" disabled readonly/>
                        <br/><br/>
                
                        <div class="dc-ruler-align">
                            <button id="dc-keygen-send-pub-btn" class="dc-button">Send Public Key</button>
                        </div>
                        <br/>
                        
                        <ul class="dc-list dc-list-red">
                            <li>Never rely on copying these keys. Use the "Send Public Key" button 
                            to send your key.</li>
                            <li>Public keys are automatically encoded with a random salts.</li>
                            <li>Posting these keys directly won't work since they aren't encoded 
                            in the format required.</li>
                        </ul>
                    </div>
                    <div class="tab-content" id="dc-handshake-tab">
                        <p style="text-align: center;">
                            <b style="font-size: large;">Key Derivation</b>
                        </p>
                        <br/>
                        
                        <p>
                            <span style="text-decoration: underline; color: #ff0000;">
                                <strong>NOTE:</strong>
                            </span>
                        </p>
                        <ul class="dc-list dc-list-red">
                            <li>Copy your partner's private key EXACTLY as it was posted.</li>
                            <li>Your last generated private key from the "Key Generation" tab 
                            will be used to compute these keys.</li>
                        </ul>
                        <br/>
                        
                        <strong>Partner's Public Key:</strong><br/>
                        <textarea id="dc-handshake-ppk" rows="8" cols="128" maxsize="16384"/>
                        <br/><br/>
                        
                        <div class="dc-ruler-align">
                            <button id="dc-handshake-paste-btn" class="dc-button dc-button-inverse">
                            Paste From Clipboard</button>
                            <button id="dc-handshake-compute-btn" class="dc-button">Compute Secret Keys</button>
                        </div>
                        
                        <ul class="dc-list dc-list-red">
                            <li id="dc-handshake-algorithm">...</li>
                            <li id="dc-handshake-salts">...</li>
                            <li id="dc-handshake-secret">...</li>
                        </ul>
                        <br/>
                        
                        <strong id="dc-handshake-prim-lbl">Primary Secret:</strong><br/>
                        <textarea id="dc-handshake-primary-key" rows="1" columns="128" maxsize="32768"
                         style="max-height: 14px;user-select: none;" unselectable="on" disabled/>
                        <br/><br/>
                        
                        <strong id="dc-handshake-sec-lbl">Secondary Secret:</strong><br/>
                        <textarea id="dc-handshake-secondary-key" rows="1" columns="128" maxsize="32768"
                         style="max-height: 14px;user-select: none;" unselectable="on" disabled/>
                        <br/><br/>
                        
                        <div class="stat stat-bar" style="width:70%;">
                            <span id="dc-exchange-status" class="stat-bar-rating" style="width: 0;"/>
                        </div><br/>
                        
                        <div class="dc-ruler-align">
                            <button id="dc-handshake-cpy-keys-btn" class="dc-button dc-button-inverse">
                            Copy Keys & Nuke</button>
                            <button id="dc-handshake-apply-keys-btn" class="dc-button">
                            Apply Generated Passwords</button>
                        </div>
                    </div>
                </div>
            </div>
            `;

        this.unlockIcon = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwIDI0I" +
            "DI0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMTdjMS4xIDAgMi0u" +
            "OSAyLTJzLS45LTItMi0yLTIgLjktMiAyIC45IDIgMiAyem02LTloLTFWNmMwLTIuNzYtMi4yNC01LTUtNVM3IDMuMjQgNyA2aDEuOWM" +
            "wLTEuNzEgMS4zOS0zLjEgMy4xLTMuMSAxLjcxIDAgMy4xIDEuMzkgMy4xIDMuMXYySDZjLTEuMSAwLTIgLjktMiAydjEwYzAgMS4xLj" +
            "kgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6bTAgMTJINlYxMGgxMnYxMHoiPjwvcGF0aD48L3N2Zz4=";

        this.lockIcon = "PHN2ZyBjbGFzcz0iZGMtc3ZnIiBmaWxsPSJsaWdodGdyZXkiIGhlaWdodD0iMjBweCIgdmlld0JveD0iMCAwIDI0IDI" +
            "0IiB3aWR0aD0iMjBweCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZGVmcz48cGF0aCBkPSJNMCAwaDI0djI0SD" +
            "BWMHoiIGlkPSJhIi8+PC9kZWZzPjxjbGlwUGF0aCBpZD0iYiI+PHVzZSBvdmVyZmxvdz0idmlzaWJsZSIgeGxpbms6aHJlZj0iI2EiL" +
            "z48L2NsaXBQYXRoPjxwYXRoIGNsaXAtcGF0aD0idXJsKCNiKSIgZD0iTTEyIDE3YzEuMSAwIDItLjkgMi0ycy0uOS0yLTItMi0yIC45" +
            "LTIgMiAuOSAyIDIgMnptNi05aC0xVjZjMC0yLjc2LTIuMjQtNS01LTVTNyAzLjI0IDcgNnYySDZjLTEuMSAwLTIgLjktMiAydjEwYzA" +
            "gMS4xLjkgMiAyIDJoMTJjMS4xIDAgMi0uOSAyLTJWMTBjMC0xLjEtLjktMi0yLTJ6TTguOSA2YzAtMS43MSAxLjM5LTMuMSAzLjEtMy" +
            "4xczMuMSAxLjM5IDMuMSAzLjF2Mkg4LjlWNnpNMTggMjBINlYxMGgxMnYxMHoiLz48L3N2Zz4=";
    }

    /* ============================================================== */

    /* ===================== STANDARD CALLBACKS ===================== */

    /* Starts the script execution. */
    start() {
        /* Backup class instance. */
        const self = this;

        /* Perform idiot-proof check to make sure the user named the plugin `discordCrypt.plugin.js` */
        if ( !discordCrypt.validPluginName() ) {
            alert(
                "Oops!\r\n\r\n" +
                "It seems you didn't read discordCrypt's usage guide. :(\r\n" +
                "You need to name this plugin exactly as follows to allow it to function correctly.\r\n\r\n" +
                "\t" + discordCrypt.getPluginName() + "\r\n\r\n\r\n" +
                "You should probably check the usage guide again just in case you missed anything else. :)",
                'Hi There! - DiscordCrypt'
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

        /* Add the toolbar. */
        this.loadToolbar();

        /* Attach the message handler. */
        this.attachHandler();

        /* Process any blocks on an interval since Discord loves to throttle messages. */
        this.scanInterval = setInterval( () => {
            self.decodeMessages();
        }, self.configFile.encryptScanDelay );

        /* The toolbar fails to properly load on switches to the friends list. Create an interval to do this. */
        this.toolbarReloadInterval = setInterval( () => {
            self.loadToolbar();
            self.attachHandler();
        }, 5000 );

        /* Don't check for updates if running a debug version. */
        if ( this.getVersion().indexOf( '-debug' ) === -1 ) {
            /* Check for any new updates. */
            this.checkForUpdates();

            /* Add an update handler to check for updates every 10 minutes. */
            this.updateHandlerInterval = setInterval( () => {
                self.checkForUpdates();
            }, 600000 );
        }
    }

    /* Stops the script execution. */
    stop() {
        /* Nothing needs to be done since start() wouldn't have triggered. */
        if ( !discordCrypt.validPluginName() )
            return;

        /* Remove onMessage event handler hook. */
        $( this.channelTextAreaClass ).off( "keydown.dcrypt" );

        /* Unload the decryption interval. */
        clearInterval( this.scanInterval );

        /* Unload the toolbar reload interval. */
        clearInterval( this.toolbarReloadInterval );

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

    /* Called when the script has to load resources. */
    load() {
        /* Inject application CSS. */
        discordCrypt.injectCSS( 'dc-css', this.appCss );

        /* Inject SJCL. */
        discordCrypt.__getRequest(
            'https://gitlab.com/riseup/up1-cli-client-nodejs/raw/master/sjcl.js',
            ( statusCode, errorString, data ) => {

                if ( statusCode !== 200 || typeof data !== 'string' ) {
                    discordCrypt.log( 'Unable to load SJCL library. Encrypted file uploads will be disabled.', 'warn' );
                    return;
                }

                require( 'vm' ).runInThisContext( data, {
                    filename: 'sjcl.js',
                    displayErrors: true
                } );
            }
        );
    }

    /* Called during application shutdown. */
    unload() {
        /* Clear the injected CSS. */
        discordCrypt.clearCSS( 'dc-css' );
    }

    /* Triggers when the channel is switched. */
    onSwitch() {
        /* Skip if no valid configuration is loaded. */
        if ( !this.configFile )
            return;

        discordCrypt.log( 'Detected chat switch.', 'debug' );

        /* Add the toolbar. */
        this.loadToolbar();

        /* Attach the message handler. */
        this.attachHandler();

        /* Decrypt any messages. */
        this.decodeMessages();
    }

    /* Attempt to decode messages once a new message has been received. */
    onMessage() {
        /* Skip if no valid configuration is loaded. */
        if ( !this.configFile )
            return;

        discordCrypt.log( 'Detected new message.', 'Decoding ...', 'debug' );

        /* Immediately decode the message. */
        this.decodeMessages();
    }

    /* =================== END STANDARD CALLBACKS =================== */

    /* =================== CONFIGURATION DATA CBS =================== */

    /* Performed when updating a configuration file across versions. */
    onUpdate() {
        /* Placeholder for future use. */
    }

    /* Returns the default settings. */
    getDefaultConfig() {
        return {
            /* Current Version. */
            version: this.getVersion(),
            /* Default password for servers not set. */
            defaultPassword: "秘一密比无为有秘习个界一万定为界人是的要人每的但了又你上着密定已",
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
            up1ApiKey: '59Mnk5nY6eCn4bi9GvfOXhMH54E7Bh6EMJXtyJfs'
        };
    }

    /* Checks if the configuration file exists. */
    configExists() {
        /* Attempt to parse the configuration file. */
        let data = bdPluginStorage.get( this.getName(), 'config' );

        /* The returned data must be defined and non-empty. */
        return data && data !== null && data !== '';
    }

    /* Loads the configuration file. */
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

        /* Try parsing the decrypted data. */
        try {
            this.configFile = JSON.parse(
                discordCrypt.aes256_decrypt_gcm( data.data, this.masterPassword, 'PKC7', 'utf8', false )
            );
        }
        catch ( err ) {
            discordCrypt.log( 'Decryption of configuration file failed - ' + err, 'error' );
            return false;
        }

        /* If it fails, return an error. */
        if ( !this.configFile || !this.configFile.version ) {
            discordCrypt.log( 'Decryption of configuration file failed.', 'error' );
            return false;
        }

        /* Check for version mismatch. */
        if ( this.configFile.version !== this.getVersion() ) {
            /* Perform whatever needs to be done before updating. */
            this.onUpdate();

            /* Preserve the old version for logging. */
            let oldVersion = this.configFile.version;

            /* Preserve the old password list before updating. */
            let oldCache = this.configFile.passList;

            /* Get the most recent default configuration. */
            this.configFile = this.getDefaultConfig();

            /* Now restore the password list. */
            this.configFile.passList = oldCache;

            /* Save the new configuration. */
            this.saveConfig();

            /* Alert. */
            discordCrypt.log( 'Updated plugin version from v' + oldVersion + ' to v' + this.getVersion() + '.' );
            return true;
        }

        discordCrypt.log( 'Loaded configuration file! - v' + this.configFile.version );
        return true;
    }

    /* Saves the configuration file. */
    saveConfig() {
        discordCrypt.log( 'Saving configuration file ...' );

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

    /* Updates and saves the configuration data used and updates a given button's text. */
    saveSettings( /* Object */ btn ) {
        /* Save self. */
        const self = this;

        /* Clear the old message decoder. */
        clearInterval( this.scanInterval );

        /* Save the configuration file. */
        this.saveConfig();

        /* Set a new decoder to use any updated configurations. */
        setInterval( function () {
            self.decodeMessages( true );
        }, this.configFile.encryptScanDelay );

        /* Tell the user that their settings were applied. */
        btn.innerHTML = "Saved & Applied!";

        /* Reset the original text after a second. */
        setTimeout( function () {
            btn.innerHTML = "Save & Apply";
        }, 1000 );
    }

    /* Resets the default configuration data used and updates a given button's text. */
    resetSettings( /* Object */ btn ) {
        /* Save self. */
        const self = this;

        /* Clear the old message decoder. */
        clearInterval( this.scanInterval );

        /* Retrieve the default configuration. */
        this.configFile = this.getDefaultConfig();

        /* Save the configuration file to update any settings. */
        this.saveConfig();

        /* Set a new decoder to use any updated configurations. */
        setInterval( function () {
            self.decodeMessages( true );
        }, self.configFile.encryptScanDelay );

        /* Tell the user that their settings were reset. */
        btn.innerHTML = "Restored Default Settings!";

        /* Reset the original text after a second. */
        setTimeout( function () {
            btn.innerHTML = "Reset Settings";
        }, 1000 );
    }

    /* Update the current password field and save the config file. */
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

    /* Returns the name of the plugin file. */
    static getPluginName() {
        return 'discordCrypt.plugin.js';
    }

    /* Check if the plugin is named correctly. */
    static validPluginName() {
        return require( 'fs' )
            .existsSync( require( 'path' )
                .join( discordCrypt.getPluginsPath(), discordCrypt.getPluginName() ) );
    }

    /* Returns the platform-specific path to BetterDiscord's plugins. */
    static getPluginsPath() {
        const process = require( 'process' );
        return (
            process.platform === 'win32' ?
                process.env.APPDATA :
                process.platform === 'darwin' ?
                    process.env.HOME + '/Library/Preferences' :
                    process.env.HOME + '/.config'
        ) + '/BetterDiscord/plugins/';
    }

    /* Checks the update server for an encrypted update.  */
    static checkForUpdate( /* function(file_data, short_hash, new_version, full_changelog) */ onUpdateCallback ) {
        /* Update URL and request method. */
        const update_url = 'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/src/' + discordCrypt.getPluginName();
        const changelog_url = 'https://gitlab.com/leogx9r/DiscordCrypt/raw/master/src/CHANGELOG';

        /* Make sure the callback is a function. */
        if ( typeof onUpdateCallback !== 'function' )
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
                            discordCrypt.log( 'Error while fetching update: ' + errorString, 'error' );
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
                }

                /* Check the first line which contains the metadata to make sure that they're equal. */
                if ( data.split( '\n' )[ 0 ] !== localFile.split( '\n' )[ 0 ] ) {
                    discordCrypt.log( 'Plugin metadata is missing from either the local or update file.', 'error' );
                    return;
                }

                /* Read the current hash of the plugin and compare them.. */
                let currentHash = discordCrypt.sha256( localFile );
                let hash = discordCrypt.sha256( data ), shortHash = new Buffer( hash, 'base64' )
                    .toString( 'hex' )
                    .slice( 0, 8 );

                /* If the hash equals the retrieved one, no update is needed. */
                if ( hash === currentHash ) {
                    discordCrypt.log( 'No Update Needed - #' + shortHash );
                    return true;
                }

                /* Try parsing a version number. */
                let version_number = '';
                try {
                    version_number = data.match( /('[0-9]+\.[0-9]+\.[0-9]+')/gi ).toString().replace( /('*')/g, '' );
                }
                catch ( e ) {
                }

                /* Now get the changelog. */
                try {
                    /* Fetch the changelog from the URL. */
                    discordCrypt.__getRequest( changelog_url, ( statusCode, errorString, changelog ) => {
                        /* Perform the callback. */
                        onUpdateCallback( data, shortHash, version_number, statusCode == 200 ? changelog : '' );
                    } );
                }
                catch ( e ) {
                    discordCrypt.log( 'Error fetching the changelog.', 'warn' );

                    /* Perform the callback without a changelog. */
                    onUpdateCallback( data, shortHash, version_number, '' );
                }
            } );
        }
        catch ( ex ) {
            /* Handle failure. */
            discordCrypt.log( 'Error while retrieving update: ' + ex.toString(), 'warn' );
            return false;
        }

        return true;
    }

    /* Returns the current message ID used by Discord. */
    static getChannelId() {
        return window.location.pathname.split( '/' ).pop();
    }

    /* Creates a password object using the parameters specified. */
    static createPassword( /* string */ primary_password, /* string */ secondary_password ) {
        return { primary: primary_password, secondary: secondary_password };
    }

    /* Returns the React modules. */
    static getReactModules() {
        /* Initializes WebPackModules. [ Credits to the creator. ] */
        const WebpackModules = ( () => {
            const req = webpackJsonp(
                [],
                { '__extra_id__': ( module, exports, req ) => exports.default = req },
                [ '__extra_id__' ]
            ).default;

            delete req.m[ '__extra_id__' ];
            delete req.c[ '__extra_id__' ];

            const find = ( filter ) => {
                for ( let i in req.c ) {
                    if ( req.c.hasOwnProperty( i ) ) {
                        let m = req.c[ i ].exports;

                        if ( m && m.__esModule && m.default )
                            m = m.default;

                        if ( m && filter( m ) )
                            return m;
                    }
                }
                for ( let i = 0; i < req.m.length; ++i ) {
                    let m = req( i );
                    if ( m && m.__esModule && m.default )
                        m = m.default;

                    if ( m && filter( m ) )
                        return m;
                }
                discordCrypt.log( 'Cannot find React module.', 'warn' );
                return null;
            };

            const findByUniqueProperties = ( propNames ) =>
                find( module => propNames.every( prop => module[ prop ] !== undefined ) );
            const findByDisplayName = ( displayName ) =>
                find( module => module.displayName === displayName );

            return { find, findByUniqueProperties, findByDisplayName };
        } )();

        return {
            ChannelProps: discordCrypt
                .__getElementReactOwner( $( 'form' )[ 0 ] ).props.channel,
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
    }

    /* Sends an embedded message. */
    static sendEmbeddedMessage(
        /* string */ embedded_text,
        /* string */ embedded_header,
        /* string */ embedded_footer,
        /* int */    embedded_color = 0x551A8B,
        /* string */ message_content = ''
    ) {
        let mention_everyone = false;

        /* Finds appropriate React modules. */
        const React = discordCrypt.getReactModules();

        /* Parse the message content to the required format if applicable.. */
        if ( typeof message_content === 'string' && message_content.length ) {
            try {
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

        /* Generate a unique nonce for this message. */
        let _nonce = parseInt( require( 'crypto' ).randomBytes( 6 ).toString( 'hex' ), 16 );

        /* Save the Channel ID. */
        let _channel = discordCrypt.getChannelId();

        /* Create the message object and add it to the queue. */
        React.MessageQueue.enqueue( {
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
                    color: embedded_color === undefined ? 0x551A8B : embedded_color,
                    timestamp: ( new Date() ).toISOString(),
                    output_mime_type: "text/x-html",
                    encoding: "utf-16",
                    author: {
                        name: embedded_header !== undefined ? embedded_header : '-----MESSAGE-----',
                        icon_url: 'https://i.imgur.com/NC0PcLA.png'
                    },
                    footer: {
                        text: embedded_footer !== undefined ? embedded_footer : 'DiscordCrypt',
                        icon_url: 'https://i.imgur.com/9y1uGB0.png'
                    },
                    description: embedded_text,
                }
            }
        }, ( r ) => {
            /* Check if an error occurred and inform Clyde bot about it. */
            if ( !r.ok ) {
                if (
                    r.status >= 400 &&
                    r.status < 500 &&
                    r.body &&
                    !React.MessageController.sendClydeError( discordCrypt.getChannelId(), r.body.code )
                )
                    discordCrypt.log( 'Error sending message: ' + r.status, 'error' );
                React.MessageDispatcher.dispatch( {
                    type: React.MessageActionTypes.ActionTypes.MESSAGE_SEND_FAILED,
                    messageId: _nonce,
                    channelId: _channel
                } );
            }
            else
            /* Receive the message normally. */
                React.MessageController.receiveMessage( _nonce, r.body );
        } );
    }

    /* Logs a message to the console. */
    static log( /* string */ message, /* string */ method = "info" ) {
        try {
            console[ method ]( "%c[DiscordCrypt]%c - " + message, "color: #7f007f; font-weight: bold;", "" );
        }
        catch ( ex ) {
        }
    }

    /* Injects a CSS style element into the header tag. */
    static injectCSS( /* string */ id, /* string */ css ) {
        /* Inject into the header tag. */
        $( "head" )
            .append( $( "<style>", { id: id.replace( /^[^a-z]+|[^\w-]+/gi, "" ), html: css } ) )
    }

    /* Clears an injected element via its ID tag. */
    static clearCSS( /* string */ id = undefined ) {
        /* Make sure the ID is a valid string. */
        if ( !id || typeof id !== 'string' || !id.length )
            return;

        /* Remove the element. */
        $( "#" + id.replace( /^[^a-z]+|[^\w-]+/gi, "" ) ).remove();
    }

    /* ================= END PROJECT UTILITIES ================= */

    /* ================= BEGIN MAIN CALLBACKS ================== */

    /* Adds the master-password field. */
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
        pwd_field.on( "keydown", function ( e ) {
            let code = e.keyCode || e.which;

            /* Execute on ENTER/RETURN only. */
            if ( code !== 13 )
                return;

            unlock_btn.click();
        } );

        /* Handle unlock button clicks. */
        unlock_btn.click( function () {

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
                new Buffer( password ),
                new Buffer( discordCrypt.whirlpool( password, true ), 'hex' ),
                32, 1536, 8, 1, ( error, progress, pwd ) => {
                    if ( error ) {
                        /* Update the button's text. */
                        if ( cfg_exists )
                            unlock_btn.text( 'Invalid Password!' );
                        else
                            unlock_btn.text( 'Error: ' + error );

                        /* Clear the text field. */
                        pwd_field[ 0 ].value = '';

                        /* Reset the progress bar. */
                        master_status.css( 'width', '0%' );

                        /* Reset the text of the button after 1 second. */
                        setTimeout( function () {
                            unlock_btn.text( action_msg );
                        }, 1000 );

                        discordCrypt.log( error.toString(), 'error' );
                        return true;
                    }

                    if ( progress )
                        master_status.css( 'width', parseInt( progress * 100 ) + '%' );

                    if ( pwd ) {
                        /* To test whether this is the correct password or not, we have to attempt to use it. */
                        self.masterPassword = new Buffer( pwd, 'hex' );

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
                            setTimeout( function () {
                                unlock_btn.text( action_msg );
                            }, 1000 );

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
                        setTimeout( function () {
                            $( '#dc-master-overlay' ).remove();
                        }, 1000 );
                    }

                    return false;
                }
            );
        } );

        /* Handle cancel button presses. */
        cancel_btn.click( function () {
            /* Use a 300 millisecond delay. */
            setTimeout(
                function () {
                    /* Remove the prompt overlay. */
                    $( '#dc-master-overlay' ).remove();

                    /* Do some quick cleanup. */
                    self.masterPassword = null;
                    self.configFile = null;
                }, 300
            );
        } );
    }

    /* Performs update checking and handles actually updating. */
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
                            alert( 'Failed to apply the update!', 'Error During Update' );
                        }
                    } );
                } );
            }
            catch ( ex ) {
                discordCrypt.log( ex, 'warn' );
            }
        }, 1000 );
    }

    /* Sets the active tab index in the exchange key menu. */
    static setActiveTab( /* int */ index ) {
        let tab_names = [ 'dc-about-tab', 'dc-keygen-tab', 'dc-handshake-tab' ];
        let tabs = $( '.dc-tab-link' );

        /* Hide all tabs. */
        for ( let i = 0; i < tab_names.length; i++ )
            $( '#' + tab_names[ i ] )[ 0 ].style.display = 'none';

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

    /* Adds the password toolbar. */
    loadToolbar() {
        /* Skip if the configuration hasn't been loaded. */
        if ( !this.configFile )
            return;

        /* Skip if we're not in an active channel. */
        if ( discordCrypt.getChannelId() === '@me' )
            return;

        /* Toolbar buttons and their icons if it doesn't exist. */
        if ( $( '#dc-passwd-btn' ).length !== 0 )
            return;

        /* Inject the toolbar. */
        $( this.searchUiClass ).parent().parent().parent().prepend( this.toolbarHtml );

        /* Set the SVG button class. */
        $( '.dc-svg' ).attr( 'class', 'dc-svg' );

        /* Set the initial status icon. */
        if ( $( '#dc-lock-btn' ).length > 0 ) {
            if ( this.configFile.encodeAll ) {
                $( '#dc-lock-btn' ).attr( 'title', 'Disable Message Encryption' );
                $( '#dc-lock-btn' )[ 0 ].innerHTML = atob( this.lockIcon );
            }
            else {
                $( '#dc-lock-btn' ).attr( 'title', 'Enable Message Encryption' );
                $( '#dc-lock-btn' )[ 0 ].innerHTML = atob( this.unlockIcon );
            }

            /* Set the button class. */
            $( '.dc-svg' ).attr( 'class', 'dc-svg' );
        }

        /* Inject the settings. */
        $( document.body ).prepend( this.settingsMenuHtml );

        /* Also by default, set the about tab to be shown. */
        discordCrypt.setActiveTab( 0 );

        /* Update all settings from the settings panel. */
        $( '#dc-settings-encrypt-trigger' )[ 0 ].value = this.configFile.encodeMessageTrigger;
        $( '#dc-settings-default-pwd' )[ 0 ].value = this.configFile.defaultPassword;
        $( '#dc-settings-scan-delay' )[ 0 ].value = this.configFile.encryptScanDelay;
        $( '#dc-settings-padding-mode' )[ 0 ].value = this.configFile.paddingMode.toLowerCase();
        $( '#dc-settings-cipher-mode' )[ 0 ].value = this.configFile.encryptBlockMode.toLowerCase();
        $( '#dc-primary-cipher' )[ 0 ].value = discordCrypt.cipherIndexToString( this.configFile.encryptMode, false );
        $( '#dc-secondary-cipher' )[ 0 ].value = discordCrypt.cipherIndexToString( this.configFile.encryptMode, true );

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
        $( '#dc-passwd-btn' ).click( discordCrypt.on_passwd_button_clicked );

        /* Update the password for the user once clicked. */
        $( '#dc-save-pwd' ).click( discordCrypt.on_save_passwords_button_clicked( this ) );

        /* Reset the password for the user to the default. */
        $( '#dc-reset-pwd' ).click( discordCrypt.on_reset_passwords_button_clicked( this ) );

        /* Hide the overlay when clicking cancel. */
        $( '#dc-cancel-btn' ).click( discordCrypt.on_cancel_password_button_clicked );

        /* Copy the current passwords to the clipboard. */
        $( '#dc-cpy-pwds-btn' ).click( discordCrypt.on_copy_current_passwords_button_clicked( this ) );

        /* Set whether auto-encryption is enabled or disabled. */
        $( '#dc-lock-btn' ).click( discordCrypt.on_lock_button_clicked( this ) );
    }

    /* Attached a handler for message events. */
    attachHandler() {
        const self = this;

        /* Get the text area. */
        let textarea = $( this.channelTextAreaClass );

        /* Make sure we got one element. */
        if ( textarea.length !== 1 )
            return;

        /* Replace any old handlers before adding the new one. */
        textarea.off( "keydown.dcrypt" ).on( "keydown.dcrypt", function ( e ) {
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

            /* Send the encrypted message. */
            self.sendEncryptedMessage( $( this ).val() );

            /* Clear text field. */
            discordCrypt.__getElementReactOwner( $( 'form' )[ 0 ] ).setState( { textValue: '' } );

            /* Cancel the default sending action. */
            e.preventDefault();
            e.stopPropagation();
        } );
    }

    /* Parses a symmetric-key message. */
    parseSymmetric( /* Object */ obj, /* string */ password, /* string */ secondary, /* Array */ ReactModules ) {
        let message = $( obj );
        let dataMsg;

        /**************************************************************************************************************
         *  MESSAGE FORMAT:
         *
         *  + 0x0000 [ 4        Chars ] - Message Magic | Key Magic
         *  + 0x0004 [ 8 ( #4 ) Chars ] - Message Metadata ( #1 ) | Key Data ( #3 )
         *  + 0x000C [ ?        Chars ] - Cipher Text
         *
         *  * 0x0004 - Options - Substituted Base64 encoding of a single word stored in Little Endian.
         *      [ 31 ... 24 ] - Algorithm ( 0-24 = Dual )
         *      [ 23 ... 16 ] - Block Mode ( 0 = CBC | 1 = CFB | 2 = OFB )
         *      [ 15 ... 08 ] - Padding Mode ( #2 )
         *      [ 07 ... 00 ] - Random Padding Byte
         *
         *  #1 - Substitute( Base64( Encryption Algorithm << 24 | Padding Mode << 16 | Block Mode << 8 | RandomByte ) )
         *  #2 - ( 0 - PKCS #7 | 1 = ANSI X9.23 | 2 = ISO 10126 | 3 = ISO97971 | 4 = Zero Pad | 5 = No Padding )
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
        if ( magic === this.encodedKeyHeader ) {
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
            button.click( function () {
                /* Save for faster access. */
                let tmp = [];
                tmp[ 'ea' ] = $( '#dc-keygen-method' )[ 0 ].value;
                tmp[ 'ks' ] = parseInt( $( '#dc-keygen-algorithm' )[ 0 ].value );

                /* Simulate pressing the exchange key button. */
                $( '#dc-exchange-btn' ).click();

                /* Extract the algorithm info from the message's metadata. */
                let metadata = discordCrypt.__extractKeyInfo( message.text().replace( /\r?\n|\r/g, '' ), true );

                /* If the current algorithm differs, change it and generate then send a new key. */
                if ( tmp[ 'ea' ] !== metadata[ 'algorithm' ] || tmp[ 'ks' ] !== metadata[ 'bit_length' ] ) {
                    /* Switch. */
                    $( '#dc-keygen-method' )[ 0 ].value = metadata[ 'algorithm' ];

                    /* Fire the change event so the second list updates. */
                    $( '#dc-keygen-method' ).change();

                    /* Update the key size. */
                    $( '#dc-keygen-algorithm' )[ 0 ].value = metadata[ 'bit_length' ];

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
                $( '#dc-handshake-ppk' )[ 0 ].value = message.text();

                /* Click compute. */
                $( '#dc-handshake-compute-btn' ).click();
            } );

            /* Add the button. */
            message.parent().append( button );

            /* Set the text to an identifiable color. */
            message.css( 'color', 'blue' );
            return true;
        }

        /* Make sure it has the correct header. */
        if ( magic !== this.encodedMessageHeader )
            return false;

        /* Try to deserialize the metadata. */
        let metadata = discordCrypt.metaDataDecode( message.text().slice( 4, 12 ) );

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
            .substr( 12 ), password, secondary, metadata[ 0 ], metadata[ 1 ], metadata[ 2 ], true );

        /* If decryption didn't fail, set the decoded text along with a green foreground. */
        if ( ( typeof dataMsg === 'string' || dataMsg instanceof String ) && dataMsg !== "" ) {
            /* Expand the message to the maximum width. */
            message.parent().parent().parent().parent().css( 'max-width', '100%' );

            /* Process the message and apply all necessary element modifications. */
            dataMsg = discordCrypt.postProcessMessage( dataMsg );

            /* Set the new HTML. */
            message[ 0 ].innerHTML = dataMsg.html;

            /* If this contains code blocks, highlight them. */
            if ( dataMsg.code ) {
                /* The inner element contains a <span></span> class, get all children beneath that. */
                let elements = $( message.children()[ 0 ] ).children();

                /* Loop over each element to get the markup division list. */
                for ( let i = 0; i < elements.length; i++ ) {
                    /* Highlight the element's <pre><code></code></code> block. */
                    ReactModules.HighlightJS.highlightBlock( $( elements[ i ] ).children()[ 0 ] );

                    /* Reset the class name. */
                    $( elements[ i ] ).children()[ 0 ].className = 'hljs';
                }
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

    /* Processes decrypted text for formatted elements. */
    static postProcessMessage(/* string */ message) {
        /* Extract any code blocks from the message. */
        let processed = discordCrypt.__buildCodeBlockMessage( message );
        let hasCode = processed.code;

        /* Extract any URLs. */
        processed = discordCrypt.__buildUrlMessage( processed.html );
        let hasUrl = processed.url;

        /* Return the raw HTML. */
        return {
            url: hasUrl,
            code: hasCode,
            html: processed.html,
        };
    }

    /* Decodes all messages in the correct format. */
    decodeMessages() {
        /* Skip if a valid configuration file has not been loaded. */
        if ( !this.configFile || !this.configFile.version )
            return;

        /* Save self. */
        const self = this;

        /* Get the current channel ID. */
        let id = discordCrypt.getChannelId();

        /* Use the default password for decryption if one hasn't been defined for this channel. */
        let password = this.configFile.passList[ id ] && this.configFile.passList[ id ].primary ?
            this.configFile.passList[ id ].primary : this.configFile.defaultPassword;
        let secondary = this.configFile.passList[ id ] && this.configFile.passList[ id ].secondary ?
            this.configFile.passList[ id ].secondary : this.configFile.defaultPassword;

        /* Look through each markup element to find an embedDescription. */
        let React = discordCrypt.getReactModules();
        $( this.messageMarkupClass ).each( function () {
            /* Skip classes with no embeds. */
            if ( !this.className.includes( 'embedDescription' ) )
                return;

            /* Skip parsed messages. */
            if ( $( this ).data( 'dc-parsed' ) !== undefined )
                return;

            /* Try parsing a symmetric message. */
            self.parseSymmetric( this, password, secondary, React );

            /* Set the flag. */
            $( this ).data( 'dc-parsed', true );
        } );
    }

    /* Sends an encrypted message to the current channel. */
    sendEncryptedMessage( /* string */ message, /* boolean */ force_send = false ) {
        /* Let's use a maximum message size of 1200 instead of 2000 to account for encoding, new line feeds & packet
         header. */
        const maximum_encoded_data = 1200;

        /* Add the message signal handler. */
        const escapeCharacters = [ "#", "/", ":" ];
        const crypto = require( 'crypto' );

        let cleaned;

        /* Skip messages starting with pre-defined escape characters. */
        if ( escapeCharacters.indexOf( message[ 0 ] ) !== -1 )
            return;

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
                return;

            /* Check if it has the trigger. */
            if ( message[ message.length - 1 ] !== this.configFile.encodeMessageTrigger )
                return;

            /* Use the first part of the message. */
            cleaned = message[ 0 ];
        }
        /* Make sure we have a valid password. */
        else
        /* Use the whole message. */
            cleaned = message;

        /* Check if we actually have a message ... */
        if ( cleaned.length === 0 )
            return;

        /* Try parsing any user-tags. */
        let parsed = discordCrypt.__extractTags( cleaned );

        /* Sanity check for messages with just spaces or new line feeds in it. */
        if ( parsed[ 0 ].length !== 0 )
        /* Extract the message to be encrypted. */
            cleaned = parsed[ 0 ];

        /* Add content tags. */
        let user_tags = parsed[ 1 ].length > 0 ? parsed[ 1 ] : '';

        /* Get the passwords. */
        let password = this.configFile.passList[ discordCrypt.getChannelId() ] ?
            this.configFile.passList[ discordCrypt.getChannelId() ].primary : this.configFile.defaultPassword;
        let secondary = this.configFile.passList[ discordCrypt.getChannelId() ] ?
            this.configFile.passList[ discordCrypt.getChannelId() ].secondary : this.configFile.defaultPassword;

        /* Returns the number of bytes a given string is in Base64. */
        function getBase64EncodedLength( len ) {
            return parseInt( ( len / 3 ) * 4 ) % 4 === 0 ? ( len / 3 ) * 4 :
                parseInt( ( len / 3 ) * 4 ) + 4 - ( parseInt( ( len / 3 ) * 4 ) % 4 );
        }

        /* If the message length is less than the threshold, we can send it without splitting. */
        if ( getBase64EncodedLength( cleaned.length ) < maximum_encoded_data ) {
            /* Encrypt the message. */
            let msg = discordCrypt.symmetricEncrypt( cleaned, password, secondary, this.configFile.encryptMode,
                this.configFile.encryptBlockMode, this.configFile.paddingMode, true );

            /* Append the header to the message normally. */
            msg = this.encodedMessageHeader + discordCrypt.metaDataEncode
            (
                this.configFile.encryptMode,
                this.configFile.encryptBlockMode,
                this.configFile.paddingMode,
                parseInt( crypto.randomBytes( 1 )[ 0 ] )
            ) + msg;

            /* Break up the message into lines. */
            msg = msg.replace( /(.{32})/g, ( e ) => {
                return e + "\r\n"
            } );

            /* Send the message. */
            discordCrypt.sendEmbeddedMessage(
                msg,
                this.messageHeader,
                'v' + this.getVersion(),
                0x551A8B,
                user_tags
            );
        }
        else {
            /* Determine how many packets we need to split this into. */
            let packets = discordCrypt.__splitStringChunks( cleaned, maximum_encoded_data );
            for ( let i = 0; i < packets.length; i++ ) {
                /* Encrypt the message. */
                let msg = discordCrypt.symmetricEncrypt( packets[ i ], password, secondary,
                    this.configFile.encryptMode, this.configFile.encryptBlockMode, this.configFile.paddingMode,
                    true
                );

                /* Append the header to the message normally. */
                msg = this.encodedMessageHeader + discordCrypt.metaDataEncode
                (
                    this.configFile.encryptMode,
                    this.configFile.encryptBlockMode,
                    this.configFile.paddingMode,
                    parseInt( crypto.randomBytes( 1 )[ 0 ] )
                ) + msg;

                /* Break up the message into lines. */
                msg = msg.replace( /(.{32})/g, ( e ) => {
                    return e + "\r\n"
                } );

                /* Send the message. */
                discordCrypt.sendEmbeddedMessage(
                    msg,
                    this.messageHeader,
                    'v' + this.getVersion(),
                    0x551A8B,
                    i === 0 ? user_tags : ''
                );
            }
        }
    }

    /* =============== BEGIN UI HANDLE CALLBACKS =============== */

    static on_file_button_clicked() {
        /* Show main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'block';

        /* Show the upload overlay. */
        $( '#dc-overlay-upload' )[ 0 ].style.display = 'block';
    }

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

    static on_upload_file_button_clicked( /* discordCrypt */ self ) {
        return () => {
            const fs = require( 'fs' );

            let file_path_field = $( '#dc-file-path' );
            let file_upload_btn = $( '#dc-file-upload-btn' );
            let message_textarea = $( '#dc-file-message-textarea' );
            let send_deletion_link = $( '#dc-file-deletion-checkbox' ).is( ':checked' );
            let randomize_file_name = $( '#dc-file-name-random-checkbox' ).is( ':checked' );

            /* Send the additional text first if it's valid. */
            if ( message_textarea.val().length > 0 )
                self.sendEncryptedMessage( message_textarea.val() );

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
                sjcl,
                ( error_string, file_url, deletion_link ) => {
                    /* Do some sanity checking. */
                    if ( error_string !== null || typeof file_url !== 'string' || typeof deletion_link !== 'string' ) {
                        /* Set the status text. */
                        file_upload_btn.text( 'Failed to upload the file!' );

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
                        `Link: ${file_url}${send_deletion_link ? '\nDelete URL: ' + deletion_link : ''}`
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
            )
        };
    }

    static on_cancel_file_upload_button_clicked() {
        /* Clear old file name. */
        $( '#dc-file-path' ).val( '' );

        /* Show main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'none';

        /* Show the upload overlay. */
        $( '#dc-overlay-upload' )[ 0 ].style.display = 'none';
    }

    static on_settings_button_clicked() {
        /* Show main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'block';

        /* Show the main settings menu. */
        $( '#dc-overlay-settings' )[ 0 ].style.display = 'block';
    }

    static on_settings_close_button_clicked() {
        /* Hide main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'none';

        /* Hide the main settings menu. */
        $( '#dc-overlay-settings' )[ 0 ].style.display = 'none';
    }

    static on_save_settings_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Update all settings from the settings panel. */
            self.configFile.encodeMessageTrigger = $( '#dc-settings-encrypt-trigger' )[ 0 ].value;
            self.configFile.encryptBlockMode = $( '#dc-settings-cipher-mode' )[ 0 ].value;
            self.configFile.defaultPassword = $( '#dc-settings-default-pwd' )[ 0 ].value;
            self.configFile.encryptScanDelay = $( '#dc-settings-scan-delay' )[ 0 ].value;
            self.configFile.paddingMode = $( '#dc-settings-padding-mode' )[ 0 ].value;
            self.configFile.encryptMode = discordCrypt
                .cipherStringToIndex( $( '#dc-primary-cipher' )[ 0 ].value, $( '#dc-secondary-cipher' )[ 0 ].value );

            $( '#dc-primary-cipher' )[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, false );
            $( '#dc-secondary-cipher' )[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, true );

            /* Handle master password updates if necessary. */
            if ( $( '#dc-master-password' )[ 0 ].value !== '' ) {
                let password = $( '#dc-master-password' )[ 0 ].value;

                /* Reset the password field. */
                $( '#dc-master-password' )[ 0 ].value = '';

                /* Hash the password. */
                discordCrypt.scrypt
                (
                    new Buffer( password ),
                    new Buffer( discordCrypt.whirlpool( password, true ), 'hex' ),
                    32, 1536, 8, 1, ( error, progress, pwd ) => {
                        if ( error ) {
                            /* Alert the user. */
                            alert( 'Error setting the new database password. Check the console for more info.' );

                            discordCrypt.log( error.toString(), 'error' );
                            return true;
                        }

                        if ( pwd ) {
                            /* Now update the password. */
                            self.masterPassword = new Buffer( pwd, 'hex' );

                            /* Save the configuration file and update the button text. */
                            self.saveSettings( this );
                        }

                        return false;
                    }
                );
            }
            else
            /* Save the configuration file and update the button text. */
                self.saveSettings( this );
        };
    }

    static on_reset_settings_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Resets the configuration file and update the button text. */
            self.resetSettings( this );

            /* Update all settings from the settings panel. */
            $( '#dc-master-password' )[ 0 ].value = '';
            $( '#dc-settings-default-pwd' )[ 0 ].value = self.configFile.defaultPassword;
            $( '#dc-settings-scan-delay' )[ 0 ].value = self.configFile.encryptScanDelay;
            $( '#dc-settings-encrypt-trigger' )[ 0 ].value = self.configFile.encodeMessageTrigger;
            $( '#dc-settings-padding-mode' )[ 0 ].value = self.configFile.paddingMode.toLowerCase();
            $( '#dc-settings-cipher-mode' )[ 0 ].value = self.configFile.encryptBlockMode.toLowerCase();
            $( '#dc-primary-cipher' )[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, false );
            $( '#dc-secondary-cipher' )[ 0 ].value = discordCrypt
                .cipherIndexToString( self.configFile.encryptMode, true );
        };
    }

    static on_restart_now_button_clicked() {
        /* Window reload is simple enough. */
        location.reload();
    }

    static on_restart_later_button_clicked() {
        /* Hide the update and changelog. */
        $( '#dc-overlay' )[ 0 ].style.display = 'none';
        $( '#dc-update-overlay' )[ 0 ].style.display = 'none';
    }

    static on_info_tab_button_clicked() {
        /* Switch to tab 0. */
        discordCrypt.setActiveTab( 0 );
    }

    static on_exchange_tab_button_clicked() {
        /* Switch to tab 1. */
        discordCrypt.setActiveTab( 1 );
    }

    static on_handshake_tab_button_clicked() {
        /* Switch to tab 2. */
        discordCrypt.setActiveTab( 2 );
    }

    static on_close_exchange_button_clicked() {
        /* Hide main background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'none';

        /* Hide the entire exchange key menu. */
        $( '#dc-overlay-exchange' )[ 0 ].style.display = 'none';
    }

    static on_open_exchange_button_clicked() {
        /* Show background. */
        $( '#dc-overlay' )[ 0 ].style.display = 'block';

        /* Show main menu. */
        $( '#dc-overlay-exchange' )[ 0 ].style.display = 'block';
    }

    static on_quick_send_public_key_button_clicked() {
        /* Don't bother opening a menu. Just generate the key. */
        $( '#dc-keygen-gen-btn' ).click();

        /* Now send it. */
        $( '#dc-keygen-send-pub-btn' ).click();
    }

    static on_exchange_algorithm_changed() {
        /* Variable bit lengths. */
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();

        /* Clear the old select list. */
        $( '#dc-keygen-algorithm option' ).each( function () {
            $( this ).remove();
        } );

        /* Repopulate the entries. */
        switch ( $( '#dc-keygen-method' )[ 0 ].value ) {
            case 'dh':
                for ( let i = 0; i < dh_bl.length; i++ ) {
                    let v = dh_bl[ i ];
                    $( '#dc-keygen-algorithm' )[ 0 ].append( new Option( v, v, i === ( dh_bl.length - 1 ) ) );
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

    static on_generate_new_key_pair_button_clicked() {
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();
        let max_salt_len = 32, min_salt_len = 16, salt_len;
        let index, raw_buffer, pub_buffer;
        let key, crypto = require( 'crypto' );

        /* Get the current algorithm. */
        switch ( $( '#dc-keygen-method' )[ 0 ].value ) {
            case 'dh':
                /* Generate a new Diffie-Hellman RSA key from the bit size specified. */
                key = discordCrypt.generateDH( parseInt( $( '#dc-keygen-algorithm' )[ 0 ].value ) );

                /* Calculate the index number starting from 0. */
                index = dh_bl.indexOf( parseInt( $( '#dc-keygen-algorithm' )[ 0 ].value ) );
                break;
            case 'ecdh':
                /* Generate a new Elliptic-Curve Diffie-Hellman key from the bit size specified. */
                key = discordCrypt.generateECDH( parseInt( $( '#dc-keygen-algorithm' )[ 0 ].value ) );

                /* Calculate the index number starting from dh_bl.length. */
                index = ( ecdh_bl.indexOf( parseInt( $( '#dc-keygen-algorithm' )[ 0 ].value ) ) + dh_bl.length );
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
        pub_buffer = new Buffer(
            key.getPublicKey( 'hex', $( '#dc-keygen-method' )[ 0 ].value === 'ecdh' ?
                'compressed' :
                undefined
            ),
            'hex'
        );

        /* Create a blank payload. */
        raw_buffer = new Buffer( 2 + salt_len + pub_buffer.length );

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

    static on_keygen_clear_button_clicked() {
        /* Clear the key textareas. */
        $( '#dc-pub-key-ta' )[ 0 ].value = $( '#dc-priv-key-ta' )[ 0 ].value = '';
    }

    static on_keygen_send_public_key_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Don't bother if it's empty. */
            if ( $( '#dc-pub-key-ta' )[ 0 ].value === '' )
                return;

            /* The text area stores a hex encoded binary. Convert it to a Base64 message to save space. */
            let message = new Buffer( $( '#dc-pub-key-ta' )[ 0 ].value, 'hex' ).toString( 'base64' );

            /* Add the header to the message and encode it. */
            message = self.encodedKeyHeader + discordCrypt.substituteMessage( message, true );

            /* Split the message by adding a new line every 32 characters like a standard PGP message. */
            let formatted_message = message.replace( /(.{32})/g, ( e ) => {
                return e + "\r\n"
            } );

            /* Calculate the algorithm string. */
            let algo_str = ( $( '#dc-keygen-method' )[ 0 ].value !== 'ecdh' ? 'DH-' : 'ECDH-' ) +
                $( '#dc-keygen-algorithm' )[ 0 ].value;

            /* Send the message. */
            let header = `-----BEGIN ${algo_str} PUBLIC KEY-----`,
                footer = `-----END ${algo_str} PUBLIC KEY----- | v${self.getVersion()}`;

            discordCrypt.sendEmbeddedMessage( formatted_message, header, footer, 0x720000 );

            /* Update the button text & reset after 1 second.. */
            $( '#dc-keygen-send-pub-btn' )[ 0 ].innerText = 'Sent The Public Key!';

            setTimeout( function () {
                $( '#dc-keygen-send-pub-btn' )[ 0 ].innerText = 'Send Public Key';
            }, 1000 );
        };
    }

    static on_handshake_paste_public_key_button_clicked() {
        $( '#dc-handshake-ppk' )[ 0 ].value = require( 'electron' ).clipboard.readText();
    }

    static on_handshake_compute_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let value, algorithm, payload, salt_len, salt, user_salt_len, user_salt;
            let isUserSaltPrimary;

            /* Provide some way of showing the user the result without actually giving it away. */
            function displaySecret( input_hex ) {
                const charset = "!@#$%^&*()_-+=[{]}\\|'\";:/?.>,<";
                let output = '';

                for ( let i = 0; i < parseInt( input_hex.length / 2 ); i++ )
                    output += charset[ parseInt( input_hex.substr( i * 2, 2 ) ) & ( charset.length - 1 ) ];

                return output;
            }

            /* Skip if no public key was entered. */
            if ( !$( '#dc-handshake-ppk' )[ 0 ].value || !$( '#dc-handshake-ppk' )[ 0 ].value.length )
                return;

            /* Skip if the user hasn't generated a key of their own. */
            if ( !$( '#dc-pub-key-ta' )[ 0 ].value || !$( '#dc-pub-key-ta' )[ 0 ].value.length ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'You Didn\'t Generate A Key!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Check if the message header is valid. */
            if (
                $( '#dc-handshake-ppk' )[ 0 ].value.replace( /\r?\n|\r/g, "" )
                    .slice( 0, 4 ) !== self.encodedKeyHeader
            )
                return;

            /* Snip off the header. */
            let blob = $( '#dc-handshake-ppk' )[ 0 ].value.replace( /\r?\n|\r/g, "" ).slice( 4 );

            /* Skip if invalid UTF-16 encoded message. */
            if ( !discordCrypt.isValidUtf16( blob ) )
                return;

            try {
                /* Decode the message. */
                let bin_str = atob( discordCrypt.substituteMessage( blob ) );

                /* Convert from a binary string to a Buffer(). */
                value = new Buffer( bin_str.length );
                for ( let i = 0; i < bin_str.length; i++ )
                    value.writeUInt8( bin_str.charCodeAt( i ), i );
            }
            catch ( e ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Invalid Public Key!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Check the algorithm they're using is the same as ours. */
            algorithm = value.readInt8( 0 );

            /* Check the algorithm is valid. */
            if ( !discordCrypt.isValidExchangeAlgorithm( algorithm ) ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Invalid Algorithm!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Read the user's generated public key. */
            let user_pub_key = new Buffer( $( '#dc-pub-key-ta' )[ 0 ].value, 'hex' );

            /* Check the algorithm used is the same as ours. */
            if ( user_pub_key.readInt8( 0 ) !== algorithm ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Mismatched Algorithm!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Update the algorithm text. */
            $( '#dc-handshake-algorithm' )[ 0 ].innerText = 'Exchange Algorithm: ' +
                discordCrypt.indexToExchangeAlgorithmString( algorithm );

            /* Get the salt length. */
            salt_len = value.readInt8( 1 );

            /* Make sure the salt length is valid. */
            if ( salt_len < 16 || salt_len > 32 ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Invalid Salt Length!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Read the public salt. */
            salt = new Buffer( value.subarray( 2, 2 + salt_len ) );

            /* Read the user's salt length. */
            user_salt_len = user_pub_key.readInt8( 1 );

            /* Read the user salt. */
            user_salt = new Buffer( user_pub_key.subarray( 2, 2 + user_salt_len ) );

            /* Update the salt text. */
            $( '#dc-handshake-salts' )[ 0 ].innerText =
                `Salts: [ ${displaySecret( salt.toString( 'hex' ) )}, ` +
                `${displaySecret( user_salt.toString( 'hex' ) )} ]`;

            /* Read the public key and convert it to a hex string. */
            payload = new Buffer( value.subarray( 2 + salt_len ) ).toString( 'hex' );

            /* Return if invalid. */
            if ( !discordCrypt.privateExchangeKey || discordCrypt.privateExchangeKey === undefined ||
                typeof discordCrypt.privateExchangeKey.computeSecret === 'undefined' ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Failed To Calculate Private Key!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Compute the local secret as a hex string. */
            let derived_secret =
                discordCrypt.computeExchangeSharedSecret( discordCrypt.privateExchangeKey, payload, false, false );

            /* Show error and quit if derivation fails. */
            if ( !derived_secret || !derived_secret.length ) {
                /* Update the text. */
                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Failed To Derive Key!';
                setTimeout( function () {
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                }, 1000 );
                return;
            }

            /* Display the first 32 characters of it. */
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
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Both Salts Are Equal ?!';
                    setTimeout(
                        function () {
                            $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                        },
                        1000
                    );
                    return;
                }
            }
            else
                isUserSaltPrimary = user_salt_len > salt_len;

            /* Create hashed salt from the two user-generated salts. */
            let primary_hash = new Buffer(
                discordCrypt.sha512( isUserSaltPrimary ? user_salt : salt, true ),
                'hex'
            );
            let secondary_hash = new Buffer(
                discordCrypt.whirlpool( isUserSaltPrimary ? salt : user_salt, true ),
                'hex'
            );

            /* Global progress for async callbacks. */
            let primary_progress = 0, secondary_progress = 0;

            /* Calculate the primary key. */
            discordCrypt.scrypt(
                new Buffer( derived_secret + secondary_hash.toString( 'hex' ), 'hex' ),
                primary_hash,
                256,
                3072,
                16,
                2,
                ( error, progress, key ) => {
                    if ( error ) {
                        /* Update the text. */
                        $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Failed Generating Primary Key!';
                        setTimeout(
                            function () {
                                $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                            },
                            1000
                        );
                        return true;
                    }

                    /* Update progress. */
                    if ( progress ) {
                        primary_progress = progress * 50;

                        $( '#dc-exchange-status' )
                            .css( 'width', parseInt( primary_progress + secondary_progress ) + '%' );
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
                        $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';

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
            let secondary_password = new Buffer(
                primary_salt.toString( 'hex' ) + derived_secret + secondary_salt.toString( 'hex' ),
                'hex'
            );

            /* Calculate the secondary key. */
            discordCrypt.scrypt( secondary_password, secondary_hash, 256, 3072, 8, 1, ( error, progress, key ) => {
                if ( error ) {
                    /* Update the text. */
                    $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Failed Generating Secondary Key!';
                    setTimeout(
                        function () {
                            $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Compute Secret Keys';
                        },
                        1000
                    );
                    return true;
                }

                if ( progress ) {
                    secondary_progress = progress * 50;
                    $( '#dc-exchange-status' ).css( 'width', parseInt( primary_progress + secondary_progress ) + '%' );
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
            $( '#dc-handshake-compute-btn' )[ 0 ].innerText = 'Generating Keys ...';

            /* Finally clear all volatile information. */
            discordCrypt.privateExchangeKey = undefined;
            $( '#dc-handshake-ppk' )[ 0 ].value = '';
            $( '#dc-priv-key-ta' )[ 0 ].value = '';
            $( '#dc-pub-key-ta' )[ 0 ].value = '';
        };
    }

    static on_handshake_copy_keys_button_clicked() {
        /* Don't bother if it's empty. */
        if ( $( '#dc-handshake-primary-key' )[ 0 ].value === '' ||
            $( '#dc-handshake-secondary-key' )[ 0 ].value === '' )
            return;

        /* Format the text and copy it to the clipboard. */
        require( 'electron' ).clipboard.writeText(
            'Primary Key: ' + $( '#dc-handshake-primary-key' )[ 0 ].value + '\r\n\r\n' +
            'Secondary Key: ' + $( '#dc-handshake-secondary-key' )[ 0 ].value
        );

        /* Nuke. */
        $( '#dc-handshake-primary-key' )[ 0 ].value = $( '#dc-handshake-secondary-key' )[ 0 ].value = '';

        /* Update the button text & reset after 1 second. */
        $( '#dc-handshake-cpy-keys-btn' )[ 0 ].innerText = 'Coped Keys To Clipboard!';

        setTimeout( function () {
            $( '#dc-handshake-cpy-keys-btn' )[ 0 ].innerText = 'Copy Keys & Nuke';
            $( '#dc-handshake-prim-lbl' ).text( 'Primary Key: ' );
            $( '#dc-handshake-sec-lbl' ).text( 'Secondary Key: ' );
        }, 1000 );
    }

    static on_handshake_apply_keys_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Skip if no primary key was generated. */
            if ( !$( '#dc-handshake-primary-key' )[ 0 ].value || !$( '#dc-handshake-primary-key' )[ 0 ].value.length )
                return;

            /* Skip if no secondary key was generated. */
            if ( !$( '#dc-handshake-secondary-key' )[ 0 ].value ||
                !$( '#dc-handshake-secondary-key' )[ 0 ].value.length )
                return;

            /* Create the password object and nuke. */
            let pwd = discordCrypt.createPassword(
                $( '#dc-handshake-primary-key' )[ 0 ].value,
                $( '#dc-handshake-secondary-key' )[ 0 ].value
            );
            $( '#dc-handshake-primary-key' )[ 0 ].value = $( '#dc-handshake-secondary-key' )[ 0 ].value = '';

            /* Apply the passwords and save the config. */
            self.configFile.passList[ discordCrypt.getChannelId() ] = pwd;
            self.saveConfig();

            /* Update the text and reset it after 1 second. */
            $( '#dc-handshake-apply-keys-btn' )[ 0 ].innerText = 'Applied & Saved!';
            setTimeout( function () {
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
            }, 1000 );
        }
    }

    static on_passwd_button_clicked() {
        $( '#dc-overlay' )[ 0 ].style.display = 'block';
        $( '#dc-overlay-password' )[ 0 ].style.display = 'block';
    }

    static on_save_passwords_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let btn = $( '#dc-save-pwd' );

            /* Update the password and save it. */
            self.updatePasswords();

            /* Update the text for the button. */
            btn.text( "Saved!" );

            /* Reset the text for the password button after a 1 second delay. */
            setTimeout( function () {
                /* Reset text. */
                btn.text( "Save Password" );

                /* Clear the fields. */
                $( "#dc-password-primary" )[ 0 ].value = '';
                $( "#dc-password-secondary" )[ 0 ].value = '';

                /* Close. */
                $( '#dc-overlay' )[ 0 ].style.display = 'none';
                $( '#dc-overlay-password' )[ 0 ].style.display = 'none';
            }, 1000 );
        };
    }

    static on_reset_passwords_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let btn = $( '#dc-reset-pwd' );

            /* Reset the configuration for this user and save the file. */
            delete self.configFile.passList[ discordCrypt.getChannelId() ];
            self.saveConfig();

            /* Update the text for the button. */
            btn.text( "Password Reset!" );

            setTimeout( function () {
                /* Reset text. */
                btn.text( "Reset Password" );

                /* Clear the fields. */
                $( "#dc-password-primary" )[ 0 ].value = '';
                $( "#dc-password-secondary" )[ 0 ].value = '';

                /* Close. */
                $( '#dc-overlay' )[ 0 ].style.display = 'none';
                $( '#dc-overlay-password' )[ 0 ].style.display = 'none';
            }, 1000 );
        };
    }

    static on_cancel_password_button_clicked() {
        /* Clear the fields. */
        $( "#dc-password-primary" )[ 0 ].value = '';
        $( "#dc-password-secondary" )[ 0 ].value = '';

        /* Close after a .25 second delay. */
        setTimeout( function () {
            /* Close. */
            $( '#dc-overlay' )[ 0 ].style.display = 'none';
            $( '#dc-overlay-password' )[ 0 ].style.display = 'none';
        }, 250 );
    }

    static on_copy_current_passwords_button_clicked( /* discordCrypt */ self ) {
        return () => {
            let currentKeys = self.configFile.passList[ discordCrypt.getChannelId() ];

            /* If no password is currently generated, write the default key. */
            if ( !currentKeys ) {
                require( 'electron' ).clipboard.writeText( 'Default Password: ' + self.configFile.defaultPassword );
                return;
            }

            /* Write to the clipboard. */
            require( 'electron' ).clipboard.writeText(
                "Primary Key: " + currentKeys.primary + "\r\n\r\n" +
                "Secondary Key: " + currentKeys.secondary
            );

            /* Alter the button text. */
            $( '#dc-cpy-pwds-btn' ).text( 'Copied Keys To Clipboard!' );

            /* Reset the button after 1 second close the prompt. */
            setTimeout( function () {
                /* Reset. */
                $( '#dc-cpy-pwds-btn' ).text( 'Copy Current Passwords!' );

                /* Close. */
                $( '#dc-cancel-btn' ).click();
            }, 1000 );
        };
    }

    static on_lock_button_clicked( /* discordCrypt */ self ) {
        return () => {
            /* Update the icon and toggle. */
            if ( !self.configFile.encodeAll ) {
                $( '#dc-lock-btn' ).attr( 'title', 'Disable Message Encryption' );
                $( '#dc-lock-btn' )[ 0 ].innerHTML = atob( self.lockIcon );
                self.configFile.encodeAll = true;
            }
            else {
                $( '#dc-lock-btn' ).attr( 'title', 'Enable Message Encryption' );
                $( '#dc-lock-btn' )[ 0 ].innerHTML = atob( self.unlockIcon );
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

    /* Performs an HTTP request returns the result to the callback. */
    static __getRequest( /* string */ url, /* function(statusCode, errorString, data) */ callback ) {
        try {
            require( 'request' )( url, ( error, response, result ) => {
                callback( response.statusCode, response.statusMessage, result );
            } );
        }
        catch ( ex ) {
            callback( -1, ex.toString() );
        }
    }

    /* Gets the React instance of an element. [ Credits to the creator. ] */
    static __getElementReactOwner(
        /* Object */    element,
        /* Array*/      {
            /* Array */ include,
            /* Array */ exclude = [ "Popout", "Tooltip", "Scroller", "BackgroundFlash" ]
        } = {}
    ) {
        if ( element === undefined )
            return undefined;

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

    /* Returns the exchange algorithm and bit size for the given metadata. */
    static __extractKeyInfo( /* string */ key_message, /* boolean */ header_present = false ) {
        try {
            let output = [];
            let msg = key_message;

            /* Strip the header if necessary. */
            if ( header_present )
                msg = msg.slice( 4 );

            /* Decode the message to Base64. */
            msg = discordCrypt.substituteMessage( msg );

            /* Decode the message to raw bytes. */
            msg = new Buffer( msg, 'base64' );

            /* Sanity check. */
            if ( !discordCrypt.isValidExchangeAlgorithm( msg[ 0 ] ) )
                return null;

            /* Buffer[0] contains the algorithm type. Reverse it. */
            output[ 'bit_length' ] = discordCrypt.indexToAlgorithmBitLength( msg[ 0 ] );
            output[ 'algorithm' ] = discordCrypt.indexToExchangeAlgorithmString( msg[ 0 ] ).split( '-' )[ 0 ].toLowerCase();

            return output;
        }
        catch ( e ) {
            return null;
        }
    }

    /* Splits the input text into chunks according to the specified length. */
    static __splitStringChunks( /* string */ input_string, /* int */ max_length ) {
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

    /* Determines if the given string is a valid username according to Discord's standards. */
    static __isValidUserName( /* string */ name ) {
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

    /* Extracts all tags from the given message. */
    static __extractTags( /* string */ message ) {
        let split_msg = message.split( ' ' );
        let cleaned_tags = '', cleaned_msg = '';
        let user_tags = [];

        /* Iterate over each segment and check for usernames. */
        for ( let i = 0, k = 0; i < split_msg.length; i++ ) {
            if ( this.__isValidUserName( split_msg[ i ] ) ) {
                user_tags[ k++ ] = split_msg[ i ];
                cleaned_msg += split_msg[ i ].split( '#' )[ 0 ] + ' ';
            }
            /* Check for @here or @everyone. */
            else if ( split_msg[ i ] === '@everyone' || split_msg[ i ] === '@here' ) {
                user_tags[ k++ ] = split_msg[ i ];
                cleaned_msg += split_msg[ i ] + ' ';
            }
            else
                cleaned_msg += split_msg[ i ] + ' ';
        }

        /* Join all tags to a single string. */
        for ( let i = 0; i < user_tags.length; i++ )
            cleaned_tags += user_tags[ i ] + ' ';

        /* Return the parsed message and user tags. */
        return [ cleaned_msg.trim(), cleaned_tags.trim() ];
    }

    /* Extracts raw code blocks from a message. */
    static __extractCodeBlocks( /* string */ message ) {
        /* This regex only extracts code blocks. */
        let code_block_expr = new RegExp( /^(([ \t]*`{3,4})([^\n]*)([\s\S]+?)(^[ \t]*\2))/gm ), _matched;

        /* Array to store all the extracted blocks in. */
        let _code_blocks = [];

        /* Loop through each tested RegExp result. */
        while ( ( _matched = code_block_expr.exec( message ) ) ) {
            /* Insert the captured data. */
            _code_blocks.push( {
                start_pos: _matched.index,
                end_pos: _matched.index + _matched[ 1 ].length,
                language: _matched[ 3 ].trim(),
                raw_code: _matched[ 4 ],
                captured_block: _matched[ 1 ]
            } );
        }

        return _code_blocks;
    }

    /* Extracts raw URLs from a message. */
    static __extractUrls( /* string */ message ) {
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

    /* Extracts code blocks from a message and formats them accordingly. */
    static __buildCodeBlockMessage( /* string */ message ) {
        try {
            /* Extract code blocks. */
            let _extracted = discordCrypt.__extractCodeBlocks( message );

            /* Throw an exception which will be caught to wrap the message normally. */
            if ( !_extracted.length )
                throw 'No code blocks available.';

            /* Loop over each expanded code block. */
            for ( let i = 0; i < _extracted.length; i++ ) {
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
                    `<pre class="hljs"><code class="dc-code-block hljs ${_extracted[ i ].language}"
                        style="position: relative;">` +
                    `<ol>${_lines}</ol></code></pre></div>`
                );
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

    /* Extracts URLs from a message and formats them accordingly. */
    static __buildUrlMessage( /* string */ message ) {
        try {
            /* Extract the URLs. */
            let _extracted = discordCrypt.__extractUrls( message );

            /* Throw an exception which will be caught to wrap the message normally. */
            if ( !_extracted.length )
                throw 'No URLs available.';

            /* Loop over each URL and format it. */
            for ( let i = 0; i < _extracted.length; i++ ) {
                /* Split the message according to the URL and replace it. */
                message =
                    message.split( _extracted[ i ] ).join( `<a href="${_extracted[ i ]}">${_extracted[ i ]}</a>` );
            }

            /* Wrap the message normally. */
            return {
                url: true,
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

    /* Returns a string, Buffer() or Array() as a buffered object. */
    static __toBuffer( /* string|Buffer|Array */ input, /* boolean */ is_input_hex = undefined ) {
        /* If the message is either a Hex, Base64 or UTF-8 encoded string, convert it to a buffer. */
        if ( typeof input === 'string' )
            return new Buffer( input, is_input_hex === undefined ? 'utf8' : is_input_hex ? 'hex' : 'base64' );
        else if ( typeof input === 'object' ) {
            /* No conversion needed, return it as-is. */
            if ( Buffer.isBuffer( input ) )
                return input;
            /* Convert the Array to a Buffer object first. */
            else if ( Array.isArray( input ) )
                return new Buffer( input );
        }

        /* Throw if an invalid type was passed. */
        throw 'Input is neither an Array(), Buffer() or a string.';
    }

    /* Creates a hash of the specified OpenSSL algorithm and returns either a hex-encoded or base64-encoded digest. */
    static __createHash(
        /* string|Buffer|Array */ message,
        /* string */              algorithm,
        /* boolean */             to_hex,
        /* boolean */             hmac,
        /* string|Buffer|Array */ secret
    ) {
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

    /* Computes a key-derivation based on the PBKDF2 standard and returns a hex or base64 encoded digest. */
    static __pbkdf2(
        /* string|Buffer|Array */ input,
        /* string|Buffer|Array */ salt,
        /* boolean */             to_hex,
        /* boolean */             is_input_hex,
        /* boolean */             is_salt_hex,
        /* function(err, hash) */ callback,
        /* string */              algorithm,
        /* int*/                  key_length,
        /* int*/                  iterations
    ) {
        const crypto = require( 'crypto' );
        let _input, _salt;

        /* Convert necessary data to Buffer objects. */
        if ( typeof input === 'object' ) {
            if ( Buffer.isBuffer( input ) )
                _input = input;
            else if ( Array.isArray )
                _input = new Buffer( input );
            else
                _input = new Buffer( input, is_input_hex === undefined ? 'utf8' : is_input_hex ? 'hex' : 'base64' );
        }
        else if ( typeof input === 'string' )
            _input = new Buffer( input, 'utf8' );

        if ( typeof salt === 'object' ) {
            if ( Buffer.isBuffer( salt ) )
                _salt = salt;
            else if ( Array.isArray )
                _salt = new Buffer( salt );
            else
                _salt = new Buffer( salt, is_salt_hex === undefined ? 'utf8' : is_salt_hex ? 'hex' : 'base64' );
        }
        else if ( typeof salt === 'string' )
            _salt = new Buffer( salt, 'utf8' );

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

    /* Pads or un-pads a given message using the specified encoding format and block size. Returns a Buffer() object. */
    static __padMessage(
        /* string|Buffer|Array */ message,
        /* string */              padding_scheme,
        /* int */                 block_size,
        /* boolean */             is_hex = undefined,
        /* boolean */             remove_padding = undefined
    ) {
        let _message, _padBytes;

        /* Returns the number of bytes required to pad a message based on the block size. */
        function __getPaddingLength( totalLength, blockSize ) {
            return totalLength % blockSize === blockSize ? blockSize : blockSize - ( totalLength % blockSize );
        }

        /* Pads a message according to the PKCS #7 / PKCS #5 format. */
        function __PKCS7( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = new Buffer( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Append the number of padding bytes according to PKCS #7 / PKCS #5 format. */
                new Buffer( paddingBytes ).fill( paddingBytes ).copy( padded, message.length );

                /* Return the result. */
                return padded;
            }
            else
            /* Remove the padding indicated by the last byte. */
                return message.slice( 0, message.length - message.readInt8( message.length - 1 ) );
        }

        /* Pads a message with null bytes. N.B. Messages must NOT end with null bytes. */
        function __ZERO( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = new Buffer( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Fill the end of the message with null bytes according to the padding length. */
                new Buffer( paddingBytes ).fill( 0x00 ).copy( message, message.length );

                /* Return the result. */
                return padded;
            }
            else {
                /* Scan backwards. */
                let lastIndex = message.length - 1;

                for ( ; lastIndex > 0; lastIndex-- )
                    /* If a null byte is encountered, split at this index. */
                    if ( message[ lastIndex ] !== 0x00 )
                        break;

                /* Slice the message based on this index. */
                return message.slice( 0, lastIndex + 1 );
            }
        }

        /* Pads a message according to the ANSI X9.23 format. */
        function __ANSIX923( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = new Buffer( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Append null-bytes till the end of the message. */
                new Buffer( paddingBytes - 1 ).fill( 0x00 ).copy( padded, message.length );

                /* Append the padding length as the final byte of the message. */
                new Buffer( 1 ).fill( paddingBytes ).copy( padded, message.length + paddingBytes - 1 );

                /* Return the result. */
                return padded;
            }
            else
            /* Remove the padding indicated by the last byte. */
                return message.slice( 0, message.length - message.readInt8( message.length - 1 ) );
        }

        /* Pads a message according to the ISO 10126 format. */
        function __ISO10126( message, paddingBytes, remove ) {
            const crypto = require( 'crypto' );

            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = new Buffer( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Copy random data to the end of the message. */
                crypto.randomBytes( paddingBytes - 1 ).copy( padded, message.length );

                /* Write the padding length at the last byte. */
                padded.writeUInt8( paddingBytes, message.length + paddingBytes - 1 );

                /* Return the result. */
                return padded;
            }
            else
            /* Remove the padding indicated by the last byte. */
                return message.slice( 0, message.length - message.readUInt8( message.length - 1 ) );
        }

        /* Pads a message according to the ISO 97971 format. */
        function __ISO97971( message, paddingBytes, remove ) {
            if ( remove === undefined ) {
                /* Allocate required padding length + message length. */
                let padded = new Buffer( message.length + paddingBytes );

                /* Copy the message. */
                message.copy( padded );

                /* Append the first byte as 0x80 */
                new Buffer( 1 ).fill( 0x80 ).copy( padded, message.length );

                /* Fill the rest of the padding with zeros. */
                new Buffer( paddingBytes - 1 ).fill( 0x00 ).copy( message, message.length + 1 );

                /* Return the result. */
                return padded;
            }
            else {
                /* Remove the null-padding. */
                let cleaned = __ZERO( message, 0, true );

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
            case 'ZR0':
                return __ZERO( _message, _padBytes, remove_padding );
            default:
                return '';
        }
    }

    /* Determines whether the passed cipher name is valid. */
    static __isValidCipher( /* string */ cipher ) {
        const crypto = require( 'crypto' );
        let isValid = false;

        /* Iterate all valid Crypto ciphers and compare the name. */
        crypto.getCiphers().every( ( s ) => {
            /* If the cipher matches, stop iterating. */
            if ( s === cipher.toLowerCase() ) {
                isValid = true;
                return false;
            }

            /* Continue iterating. */
            return true;
        } );

        /* Return the result. */
        return isValid;
    }

    /* Converts a given key or iv into a buffer object. Performs a hash of the key it doesn't match the blockSize. */
    static __validateKeyIV(
        /* string|Buffer|Array */ key,
        /* int */                 key_size_bits = 256,
        /* boolean */             use_whirlpool = undefined
    ) {
        /* Get the designed hashing algorithm. */
        let keyBytes = key_size_bits / 8;

        /* If the length of the key isn't of the desired size, hash it. */
        if ( key.length !== keyBytes ) {
            let hash;

            /* Get the appropriate hasher for the key size. */
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
            return new Buffer( hash( key, true ), 'hex' );
        }
        else {
            if ( typeof key === 'string' ||
                ( typeof key === 'object' && ( Buffer.isBuffer( key ) || Array.isArray( key ) ) ) )
                return new Buffer( key );
            else
                throw 'exception - Invalid key type.';
        }
    }

    /* Convert the message to a buffer object. Supported formats are: String, Buffer, Array. */
    static __validateMessage( /* string|Buffer|Array */ message, /* boolean */ is_message_hex = undefined ) {
        /* Convert the message to a buffer. */
        try {
            return discordCrypt.__toBuffer( message, is_message_hex );
        }
        catch ( e ) {
            throw 'exception - Invalid message type.';
        }
    }

    /* Encrypts the given plain-text message using the algorithm specified. */
    static __encrypt(
        /* string */              symmetric_cipher,
        /* string */              block_mode,
        /* string */              padding_scheme,
        /* string|Buffer|Array */ message,
        /* string|Buffer|Array */ key,
        /* boolean */             convert_to_hex,
        /* boolean */             is_message_hex,
        /* int */                 key_size_bits = 256,
        /* int */                 block_cipher_size = 128,
        /* string|Buffer|Array */ one_time_salt = undefined
    ) {
        const cipher_name = symmetric_cipher + ( block_mode === undefined ? '' : '-' + block_mode );
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
                _salt = new Buffer( discordCrypt.whirlpool64( _salt, true ), 'hex' );
        }
        else
        /* Generate a random salt to derive the key and IV. */
            _salt = crypto.randomBytes( 8 );

        /* Derive the key length and IV length. */
        _derived = discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), 1000 );

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
        return new Buffer( _salt.toString( 'hex' ) + _ct, 'hex' ).toString( convert_to_hex ? 'hex' : 'base64' );
    }

    /* Decrypts the given cipher-text message using the algorithm specified. */
    static __decrypt(
        /* string */              symmetric_cipher,
        /* string */              block_mode,
        /* string */              padding_scheme,
        /* string|Buffer|Array */ message,
        /* string|Buffer|Array */ key,
        /* string */              output_format,
        /* boolean */             is_message_hex,
        /* int */                 key_size_bits = 256,
        /* int */                 block_cipher_size = 128
    ) {
        const cipher_name = symmetric_cipher + ( block_mode === undefined ? '' : '-' + block_mode );
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
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), 1000 );

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

    /* Returns the string encoded mime type of a file. */
    static __up1GetMimeType( /* string */ file_path ) {
        /* Look up the Mime type from the file extension. */
        let type = require( 'mime-types' ).lookup( require( 'path' ).extname( file_path ) );

        /* Default to an octet stream if it fails. */
        return type === false ? 'application/octet-stream' : type;
    }

    static __up1EncryptData(
        /* string */ file_path,
        /* class */ sjcl,
        /* function(error_string, encrypted_data, identity, encoded_seed) */ callback,
        /* boolean */ randomize_file_name = false
    ) {
        const crypto = require( 'crypto' );
        const path = require( 'path' );
        const fs = require( 'fs' );

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
            let buf = new Buffer( str.length * 2 );

            /* Loop over each byte. */
            for ( let i = 0, strLen = str.length; i < strLen; i++ )
                /* Write the UTF-16 equivalent in Big Endian. */
                buf.writeUInt16BE( str.charCodeAt( i ), i * 2 );
            return buf;
        }

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

                /* Calculate the upload header and append the file data to it prior to encryption. */
                file_data = Buffer.concat( [
                    str2ab( JSON.stringify( {
                        'mime': discordCrypt.__up1GetMimeType( file_path ),
                        'name': randomize_file_name ?
                            crypto.pseudoRandomBytes( 8 ).toString( 'hex' ) + path.extname( file_path ) :
                            path.basename( file_path )
                    } ) ),
                    new Buffer( [ 0, 0 ] ),
                    file_data
                ] );

                /* Convert the file to a Uint8Array() then to SJCL's bit buffer. */
                file_data = sjcl.codec.bytes.toBits( new Uint8Array( file_data ) );

                /* Generate a random 128 bit seed and calculate the key and IV from this. */
                let params = getParams( crypto.randomBytes( 16 ) );

                /* Perform AES-256-CCM encryption on this buffer and return an ArrayBuffer() object. */
                file_data = sjcl.arrayBuffer.ccm
                    .compat_encrypt( new sjcl.cipher.aes( params.key ), file_data, params.iv );

                /* Execute the callback. */
                callback(
                    null,
                    new Buffer( sjcl.codec.bytes.fromBits( file_data ) ),
                    sjcl.codec.base64url.fromBits( params.ident ),
                    sjcl.codec.base64url.fromBits( params.seed )
                );
            } );
        }
        catch ( ex ) {
            callback( ex.toString() );
        }
    }

    static __up1UploadFile(
        /* string */ file_path,
        /* string */ up1_host,
        /* string */ up1_api_key,
        /* class */ sjcl,
        /* function(error_string, file_url, deletion_link, encoded_seed) */ callback,
        /* boolean */ randomize_file_name = false
    ) {
        /* Encrypt the file data first. */
        this.__up1EncryptData(
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
                        uri: up1_host + '/up',
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
                                    up1_host + '/#' + encoded_seed,
                                    up1_host + `/del?ident=${identity}&delkey=${JSON.parse( body ).delkey}`,
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

    /* Performs the Scrypt hash function on the given input.
     * Original Implementation: https://github.com/ricmoo/scrypt-js
     * Param: input - Input data. Must be either a Buffer, Array or a UTF-8 encoded string.
     * Param: salt - Initialization salt. Must be either a Buffer, Array or a UTF-8 encoded string.
     * Param: dkLen - The length of the derived key.
     * Param: N - The work factor variable. Memory and CPU usage scale linearly with this.
     * Param: r - Increases the size of each hash produced by a factor of 2rK-bits.
     * Param: p - Parallelization factor. Indicates the number of mixing functions to be run simultaneously.
     * Param: cb(error, progress, key) - Callback function for progress updates.
     *          Callback must return false repeatedly upon each call to have Scrypt continue running.
     *          Once [progress] === 1.f AND [key] is defined, no further calls will be made.
     * Returns: Returns true if successful.
    */
    static scrypt(
        /* Buffer|Array|string */               input,
        /* Buffer|Array|string */               salt,
        /* int */                               dkLen,
        /* int */                               N = 16384,
        /* int */                               r = 8,
        /* int */                               p = 1,
        /* function(error, progress, result) */ cb = null
    ) {
        let _in, _salt;

        /* PBKDF2-HMAC-SHA256 Helper. */
        function PBKDF2_SHA256( input, salt, size, iterations ) {
            try {
                return new Buffer(
                    discordCrypt.pbkdf2_sha256( input, salt, true, undefined, undefined, size, iterations ),
                    'hex'
                );
            }
            catch ( e ) {
                discordCrypt.log( e.toString(), 'error' );
                return new Buffer();
            }
        }

        /* Performs an XOR on a block. */
        function XOR_BLOCK( S, Si, D, L ) {
            for ( let i = 0; i < L; i++ )
                D[ i ] ^= S[ Si + i ];
        }

        /* Copies the source array to the destination array. */
        function ArrayCopy( src, srcPos, dest, destPos, length ) {
            while ( length-- )
                dest[ destPos++ ] = src[ srcPos++ ];
        }

        /* Performs SALSA-20 on the block. */
        function XSALSA_20( B, x ) {
            ArrayCopy( B, 0, x, 0, 16 );

            /**
             * @return {number}
             */
            function R( a, b ) {
                return ( a << b ) | ( a >>> ( 32 - b ) );
            }

            for ( let i = 8; i > 0; i -= 2 ) {
                x[ 4 ] ^= R( x[ 0 ] + x[ 12 ], 7 );
                x[ 8 ] ^= R( x[ 4 ] + x[ 0 ], 9 );
                x[ 12 ] ^= R( x[ 8 ] + x[ 4 ], 13 );
                x[ 0 ] ^= R( x[ 12 ] + x[ 8 ], 18 );
                x[ 9 ] ^= R( x[ 5 ] + x[ 1 ], 7 );
                x[ 13 ] ^= R( x[ 9 ] + x[ 5 ], 9 );
                x[ 1 ] ^= R( x[ 13 ] + x[ 9 ], 13 );
                x[ 5 ] ^= R( x[ 1 ] + x[ 13 ], 18 );
                x[ 14 ] ^= R( x[ 10 ] + x[ 6 ], 7 );
                x[ 2 ] ^= R( x[ 14 ] + x[ 10 ], 9 );
                x[ 6 ] ^= R( x[ 2 ] + x[ 14 ], 13 );
                x[ 10 ] ^= R( x[ 6 ] + x[ 2 ], 18 );
                x[ 3 ] ^= R( x[ 15 ] + x[ 11 ], 7 );
                x[ 7 ] ^= R( x[ 3 ] + x[ 15 ], 9 );
                x[ 11 ] ^= R( x[ 7 ] + x[ 3 ], 13 );
                x[ 15 ] ^= R( x[ 11 ] + x[ 7 ], 18 );
                x[ 1 ] ^= R( x[ 0 ] + x[ 3 ], 7 );
                x[ 2 ] ^= R( x[ 1 ] + x[ 0 ], 9 );
                x[ 3 ] ^= R( x[ 2 ] + x[ 1 ], 13 );
                x[ 0 ] ^= R( x[ 3 ] + x[ 2 ], 18 );
                x[ 6 ] ^= R( x[ 5 ] + x[ 4 ], 7 );
                x[ 7 ] ^= R( x[ 6 ] + x[ 5 ], 9 );
                x[ 4 ] ^= R( x[ 7 ] + x[ 6 ], 13 );
                x[ 5 ] ^= R( x[ 4 ] + x[ 7 ], 18 );
                x[ 11 ] ^= R( x[ 10 ] + x[ 9 ], 7 );
                x[ 8 ] ^= R( x[ 11 ] + x[ 10 ], 9 );
                x[ 9 ] ^= R( x[ 8 ] + x[ 11 ], 13 );
                x[ 10 ] ^= R( x[ 9 ] + x[ 8 ], 18 );
                x[ 12 ] ^= R( x[ 15 ] + x[ 14 ], 7 );
                x[ 13 ] ^= R( x[ 12 ] + x[ 15 ], 9 );
                x[ 14 ] ^= R( x[ 13 ] + x[ 12 ], 13 );
                x[ 15 ] ^= R( x[ 14 ] + x[ 13 ], 18 );
            }

            for ( let i = 0; i < 16; ++i )
                B[ i ] += x[ i ];
        }

        /* Mixes a block and performs SALSA20 on it. */
        function BLOCKMIX_SALSA20( BY, Yi, r, x, _X ) {
            let i;

            ArrayCopy( BY, ( 2 * r - 1 ) * 16, _X, 0, 16 );

            for ( i = 0; i < 2 * r; i++ ) {
                XOR_BLOCK( BY, i * 16, _X, 16 );
                XSALSA_20( _X, x );
                ArrayCopy( _X, 0, BY, Yi + ( i * 16 ), 16 );
            }

            for ( i = 0; i < r; i++ )
                ArrayCopy( BY, Yi + ( i * 2 ) * 16, BY, ( i * 16 ), 16 );

            for ( i = 0; i < r; i++ )
                ArrayCopy( BY, Yi + ( i * 2 + 1 ) * 16, BY, ( i + r ) * 16, 16 );
        }

        /* Perform the script process. */
        function __perform( input, salt, N, r, p, cb ) {
            let totalOps, currentOp, lastPercent10;
            let b = PBKDF2_SHA256( input, salt, p * 128 * r, 1 );
            let B = new Uint32Array( p * 32 * r );

            /* Initialize the input. */
            for ( let i = 0; i < B.length; i++ ) {
                let j = i * 4;
                B[ i ] =
                    ( ( b[ j + 3 ] & 0xff ) << 24 ) |
                    ( ( b[ j + 2 ] & 0xff ) << 16 ) |
                    ( ( b[ j + 1 ] & 0xff ) << 8 ) |
                    ( ( b[ j ] & 0xff ) << 0 );
            }

            let XY = new Uint32Array( 64 * r );
            let V = new Uint32Array( 32 * r * N );

            let Yi = 32 * r;

            // Scratchpad
            let x = new Uint32Array( 16 );        // XSALSA_20
            let _X = new Uint32Array( 16 );       // BLOCKMIX_XSALSA20

            totalOps = p * N * 2;
            currentOp = 0;
            lastPercent10 = null;

            // Set this to true to abandon the scrypt on the next step
            let stop = false;

            // State information
            let state = 0;
            let i0 = 0, i1;
            let Bi;

            // How many block-mix salsa8 operations can we do per step?
            let limit = parseInt( 1000 / r );

            // Trick from scrypt-async; if there is a setImmediate shim in place, use it
            let nextTick = ( typeof( setImmediate ) !== 'undefined' ) ? setImmediate : setTimeout;

            const incrementalSMix = function () {
                if ( stop )
                    return cb( new Error( 'cancelled' ), currentOp / totalOps );

                let steps, i, percent10;
                switch ( state ) {
                    case 0:
                        // for (var i = 0; i < p; i++)...
                        Bi = i0 * 32 * r;
                        ArrayCopy( B, Bi, XY, 0, Yi );                        // ROMix - 1
                        state = 1;                                            // Move to ROMix 2
                        i1 = 0;
                    // Fall through
                    case 1:
                        // Run up to 1000 steps of the first inner S-Mix loop
                        steps = N - i1;

                        if ( steps > limit )
                            steps = limit;

                        for ( i = 0; i < steps; i++ ) {                       // ROMix - 2
                            ArrayCopy( XY, 0, V, ( i1 + i ) * Yi, Yi );       // ROMix - 3
                            BLOCKMIX_SALSA20( XY, Yi, r, x, _X );             // ROMix - 4
                        }

                        // for (var i = 0; i < N; i++)
                        i1 += steps;
                        currentOp += steps;

                        // Call the callback with the progress ( Optionally stopping us. )
                        percent10 = parseInt( 1000 * currentOp / totalOps );
                        if ( percent10 !== lastPercent10 ) {
                            stop = cb( null, currentOp / totalOps );

                            if ( stop )
                                break;

                            lastPercent10 = percent10;
                        }

                        if ( i1 < N )
                            break;

                        i1 = 0;                                               // ROMix - 6
                        state = 2;
                    // Fall through
                    case 2:

                        // Run up to 1000 steps of the second inner S-Mix loop
                        steps = N - i1;

                        if ( steps > limit ) steps = limit;

                        for ( i = 0; i < steps; i++ ) {
                            const offset = ( 2 * r - 1 ) * 16;                // ROMix - 6
                            const j = XY[ offset ] & ( N - 1 );               // ROMix - 7
                            XOR_BLOCK( V, j * Yi, XY, Yi );                   // ROMix - 8 (inner)
                            BLOCKMIX_SALSA20( XY, Yi, r, x, _X );             // ROMix - 9 (outer)
                        }

                        // for (var i = 0; i < N; i++)...
                        i1 += steps;
                        currentOp += steps;

                        // Call the callback with the progress (optionally stopping us)
                        percent10 = parseInt( 1000 * currentOp / totalOps );
                        if ( percent10 !== lastPercent10 ) {
                            stop = cb( null, currentOp / totalOps );

                            if ( stop )
                                break;

                            lastPercent10 = percent10;
                        }

                        if ( i1 < N )
                            break;

                        ArrayCopy( XY, 0, B, Bi, Yi );                        // ROMix - 10

                        // for (var i = 0; i < p; i++)...
                        i0++;
                        if ( i0 < p ) {
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

                        const derivedKey = PBKDF2_SHA256( input, new Buffer( b ), dkLen, 1 );

                        // Done; don't break (which would reschedule)
                        return cb( null, 1.0, new Buffer( derivedKey ) );
                    default:
                        return cb( new Error( 'invalid state' ), 0 );
                }

                // Schedule the next steps
                nextTick( incrementalSMix );
            };

            incrementalSMix();
        }

        /* Validate input. */
        if ( typeof input === 'object' || typeof input === 'string' ) {
            if ( Array.isArray( input ) )
                _in = new Buffer( input );
            else if ( Buffer.isBuffer( input ) )
                _in = input;
            else if ( typeof input === 'string' )
                _in = new Buffer( input, 'utf8' );
            else {
                discordCrypt.log( 'Invalid input parameter type specified!', 'error' );
                return false;
            }
        }

        /* Validate salt. */
        if ( typeof salt === 'object' || typeof salt === 'string' ) {
            if ( Array.isArray( salt ) )
                _salt = new Buffer( salt );
            else if ( Buffer.isBuffer( salt ) )
                _salt = salt;
            else if ( typeof salt === 'string' )
                _salt = new Buffer( salt, 'utf8' );
            else {
                discordCrypt.log( 'Invalid salt parameter type specified!', 'error' );
                return false;
            }
        }

        /* Validate derived key length. */
        if ( typeof dkLen !== 'number' ) {
            discordCrypt.log( 'Invalid dkLen parameter specified. Must be a numeric value.', 'error' );
            return false;
        }
        else if ( dkLen <= 0 || dkLen >= 65536 ) {
            discordCrypt.log( 'Invalid dkLen parameter specified. Must be a numeric value.', 'error' );
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

    /* Returns the first 64 bits of a Whirlpool digest of the message. */
    static whirlpool64( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return new Buffer( discordCrypt.whirlpool( message, true ), 'hex' )
            .slice( 0, 8 ).toString( to_hex ? 'hex' : 'base64' );
    }

    /* Returns the first 128 bits of an SHA-512 digest of a message. */
    static sha512_128( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return new Buffer( discordCrypt.sha512( message, true ), 'hex' )
            .slice( 0, 16 ).toString( to_hex ? 'hex' : 'base64' );
    }

    /* Returns the first 192 bits of a Whirlpool digest of the message. */
    static whirlpool192( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return new Buffer( discordCrypt.sha512( message, true ), 'hex' )
            .slice( 0, 24 ).toString( to_hex ? 'hex' : 'base64' );
    }

    /* Returns an SHA-160 digest of the message. */
    static sha160( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'sha1', to_hex );
    }

    /* Returns an SHA-256 digest of the message. */
    static sha256( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'sha256', to_hex );
    }

    /* Returns an SHA-512 digest of the message. */
    static sha512( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'sha512', to_hex );
    }

    /* Returns a Whirlpool-512 digest of the message. */
    static whirlpool( /* Buffer|Array|string */ message, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'whirlpool', to_hex );
    }

    /* Returns a HMAC-SHA-256 digest of the message. */
    static hmac_sha256( /* Buffer|Array|string */ message, /* Buffer|Array|string */ secret, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'sha256', to_hex, true, secret );
    }

    /* Returns an HMAC-SHA-512 digest of the message. */
    static hmac_sha512( /* Buffer|Array|string */ message, /* Buffer|Array|string */ secret, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'sha512', to_hex, true, secret );
    }

    /* Returns an HMAC-Whirlpool-512 digest of the message. */
    static hmac_whirlpool( /* Buffer|Array|string */ message, /* Buffer|Array|string */ secret, /* boolean */ to_hex ) {
        return discordCrypt.__createHash( message, 'whirlpool', to_hex, true, secret );
    }

    /* Computes a derived digest using the PBKDF2 algorithm and SHA-256 as primitives. */
    static pbkdf2_sha256(
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
            'sha256',
            key_length,
            iterations
        );
    }

    /* Computes a derived digest using the PBKDF2 algorithm and SHA-512 as primitives. */
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

    /* Computes a derived digest using the PBKDF2 algorithm and Whirlpool-512 as primitives. */
    static pbkdf2_whirlpool(
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
            'whirlpool',
            key_length,
            iterations
        );
    }

    /* ============ END NODE CRYPTO HASH PRIMITIVES ============ */

    /* ================ CRYPTO CIPHER FUNCTIONS ================ */

    /* Blowfish encrypts a message. If the key specified is not 512 bits in length, it is hashed via Whirlpool. */
    static blowfish512_encrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* boolean */               to_hex = false,
        /* boolean */               is_message_hex = undefined,
        /* string|Buffer|Array */   one_time_salt = undefined
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
            one_time_salt
        );
    }

    /* Blowfish decrypts a message. If the key specified is not 512 bits in length, it is hashed via Whirlpool. */
    static blowfish512_decrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* string */                output_format = 'utf8',
        /* boolean */               is_message_hex = undefined
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
            blockSize
        );
    }

    /* AES-256 encrypts a message. Message must be a modulo of the block size and key to be the same block size. */
    static aes256_encrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* boolean */               to_hex = false,
        /* boolean */               is_message_hex = undefined,
        /* string|Buffer|Array */   one_time_salt = undefined
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
            one_time_salt
        );
    }

    /* AES-256 decrypts a message. Message must be a modulo of the block size and key & iv to be the same block size. */
    static aes256_decrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* string */                output_format = 'utf8',
        /* boolean */               is_message_hex = undefined
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
            blockSize
        );
    }

    /* AES-256 decrypts a message in GCM mode. Message must be a modulo of the block size and key & iv to be the
     same block size. */
    static aes256_encrypt_gcm(
        /* string|Buffer|Array */ message,
        /* string|Buffer|Array */ key,
        /* string */              padding_mode,
        /* boolean */             to_hex = false,
        /* boolean */             is_message_hex = undefined,
        /* string|Buffer|Array */ additional_data = undefined,
        /* string|Buffer|Array */ one_time_salt = undefined
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
                _salt = new Buffer( discordCrypt.whirlpool64( _salt, true ), 'hex' );
        }
        else
        /* Generate a random salt to derive the key and IV. */
            _salt = crypto.randomBytes( 8 );

        /* Derive the key length and IV length. */
        _derived = discordCrypt.pbkdf2_sha256( _key.toString( 'hex' ), _salt.toString( 'hex' ), true, true, true,
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), 1000 );

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
        return new Buffer(
            _encrypt.getAuthTag().toString( 'hex' ) + _salt.toString( 'hex' ) + _ct,
            'hex'
        ).toString( to_hex ? 'hex' : 'base64' );
    }

    /* AES-256 decrypts a message in GCM mode. Message must be a modulo of the block size and key & iv to be the same
     block size. */
    static aes256_decrypt_gcm(
        /* string|Buffer|Array */ message,
        /* string|Buffer|Array */ key,
        /* string */              padding_mode,
        /* string */              output_format = 'utf8',
        /* boolean */             is_message_hex = undefined,
        /* string|Buffer|Array */ additional_data = undefined
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
            ( block_cipher_size / 8 ) + ( key_size_bits / 8 ), 1000 );

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

    /* Camellia-256 encrypts a message. If the key specified is not 256 bits in length, it is hashed via SHA-256. */
    static camellia256_encrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* boolean */               to_hex = false,
        /* boolean */               is_message_hex = undefined,
        /* string|Buffer|Array */   one_time_salt = undefined
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
            one_time_salt
        );
    }

    /* Camellia-256 decrypts a message. If the key specified is not 256 bits in length, it is hashed via SHA-256. */
    static camellia256_decrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* string */                output_format = 'utf8',
        /* boolean */               is_message_hex = undefined
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
            blockSize
        );
    }

    /* TripleDES-192 encrypts a message. If the key specified is not 192 bits in length, it is hashed via
     Whirlpool-192. */
    static tripledes192_encrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* boolean */               to_hex = false,
        /* boolean */               is_message_hex = undefined,
        /* string|Buffer|Array */   one_time_salt = undefined
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
            one_time_salt
        );
    }

    /* TripleDES-192 decrypts a message. If the key specified is not 192 bits in length, it is hashed via
     Whirlpool-192. */
    static tripledes192_decrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* string */                output_format = 'utf8',
        /* boolean */               is_message_hex = undefined
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
            blockSize
        );
    }

    /* IDEA-128 encrypts a message. If the key specified is not 128 bits in length, it is hashed via SHA-512-128. */
    static idea128_encrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* boolean */               to_hex = false,
        /* boolean */               is_message_hex = undefined,
        /* string|Buffer|Array */   one_time_salt = undefined
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
            one_time_salt
        );
    }

    /* IDEA-128 decrypts a message. If the key specified is not 128 bits in length, it is hashed via SHA-512-128. */
    static idea128_decrypt(
        /* string|Buffer|Array */   message,
        /* string|Buffer|Array */   key,
        /* string */                cipher_mode,
        /* string */                padding_mode,
        /* string */                output_format = 'utf8',
        /* boolean */               is_message_hex = undefined
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
            blockSize
        );
    }

    /* ============== END CRYPTO CIPHER FUNCTIONS ============== */

    /* Converts a cipher string to its appropriate index number. */
    static cipherStringToIndex( /* string */ primary_cipher, /* string */ secondary_cipher = undefined ) {
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

    /* Converts an algorithm index to its appropriate string value. */
    static cipherIndexToString( /* int */ index, /* boolean */ get_secondary = undefined ) {

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

    /* Converts an input string to the approximate entropic bits using Shannon's algorithm. */
    static entropicBitLength( /* string */ key ) {
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

    /* Retrieves UTF-16 charset as an Array Object. */
    static getUtf16() {
        return Array.from(
            "㐀㐁㐂㐃㐄㐅㐇㐒㐓㐔㐕㐖㐗㐜㐞㐡㐣㐥㐧㐨㐩㐫㐪㐭㐰㐱㐲㐳㐴㐶㐷㐹㐼㐽㐿㑁㑂㑃㑅㑇㑈㑉㑊㑏㑑" +
            "㑒㑓㑕㑣㑢㑡㑠㑟㑞㑝㑜㑤㑥㑦㑧㑨㑩㑪㑫㑵"
        );
    }

    /* Determines if a string has all valid UTF-16 characters. */
    static isValidUtf16( /* string */ message ) {
        let c = discordCrypt.getUtf16();
        let m = message.split( '' ).join( '' );

        for ( let i = 0; i < m.length; i++ )
            if ( c.indexOf( m[ i ] ) === -1 )
                return false;

        return true;
    }

    /* Retrieves Base64 charset as an Array Object. */
    static getBase64() {
        return Array.from( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" );
    }

    /* Determines if a string has all valid Base64 characters. */
    static isValidBase64( /* string */ message ) {
        try {
            btoa( message );
            return true;
        } catch ( e ) {
            return false;
        }
    }

    /* Returns an array of valid Diffie-Hellman exchange key bit-sizes. */
    static getDHBitSizes() {
        return [ 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192 ];
    }

    /* Returns an array of Elliptic-Curve Diffie-Hellman key bit-sizes. */
    static getECDHBitSizes() {
        return [ 224, 256, 384, 409, 521, 571 ];
    }

    /* Determines if a key exchange algorithm's index is valid. */
    static isValidExchangeAlgorithm( /* int */ index ) {
        return index >= 0 &&
            index <= ( discordCrypt.getDHBitSizes().length + discordCrypt.getECDHBitSizes().length - 1 );
    }

    /* Converts an algorithm index to a string. */
    static indexToExchangeAlgorithmString( /* int */ index ) {
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();
        let base = [ 'DH-', 'ECDH-' ];

        if ( !discordCrypt.isValidExchangeAlgorithm( index ) )
            return 'Invalid Algorithm';

        return ( index <= ( dh_bl.length - 1 ) ?
            base[ 0 ] + dh_bl[ index ] :
            base[ 1 ] + ecdh_bl[ index - dh_bl.length ] );
    }

    /* Converts an algorithm index to a bit size. */
    static indexToAlgorithmBitLength( /* int */ index ) {
        let dh_bl = discordCrypt.getDHBitSizes(), ecdh_bl = discordCrypt.getECDHBitSizes();

        if ( !discordCrypt.isValidExchangeAlgorithm( index ) )
            return 0;

        return ( index <= ( dh_bl.length - 1 ) ? dh_bl[ index ] : ecdh_bl[ index - dh_bl.length ] );
    }

    /* Computes a secret key from two ECDH or DH keys. One private and one public. */
    static computeExchangeSharedSecret(
        /* ECDH|DH */  private_key,
        /* ECDH|DH */  public_key,
        /* boolean */  is_base_64,
        /* boolean */  to_base_64
    ) {
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

    /* Generates a Diffie-Hellman Key. */
    static generateDH( /* int */ size, /* Buffer */ private_key = undefined ) {
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

    /* Generates an Elliptic-Curve Diffie-Hellman Key. */
    static generateECDH( /* int */ size, /* Buffer */ private_key = undefined ) {
        let groupName, key;

        /* Calculate the appropriate group. */
        switch ( size ) {
            case 224:
                groupName = 'secp224r1';
                break;
            case 256:
                groupName = 'secp256k1';
                break;
            case 384:
                groupName = 'secp384r1';
                break;
            case 409:
                groupName = 'sect409r1';
                break;
            case 521:
                groupName = 'secp521r1';
                break;
            case 571:
                groupName = 'sect571r1';
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

    /* Substitutes input Base64 to Chinese character set. */
    static substituteMessage( /* string */ message, /* boolean */ to_base64 ) {
        /* Target character set. */
        let subset = discordCrypt.getUtf16();

        /* Base64-Character set. */
        let original = discordCrypt.getBase64();

        let result = "", index = 0;

        if ( to_base64 !== undefined ) {
            /* Calculate the target character. */
            for ( let i = 0; i < message.length; i++ ) {
                index = original.indexOf( message[ i ] );

                /* Sanity check. */
                if ( index === -1 )
                    throw 'Message contains invalid characters.';

                result += subset[ index ];
            }

            /* Strip the extra UTF16 character that might somehow be added. */
            result = result.split( '' ).join( '' );
        }
        else {
            /* Strip the extra UTF16 character then decode the message. */
            message = message.split( '' ).join( '' );

            /* Calculate the target character. */
            for ( let i = 0; i < message.length; i++ ) {
                index = subset.indexOf( message[ i ] );

                /* Sanity check. */
                if ( index === -1 )
                    throw 'Message contains invalid characters.';

                result += original[ subset.indexOf( message[ i ] ) ];
            }
        }

        return result;
    }

    /* Encodes the given values as a Base64 encoded 32-bit word. */
    static metaDataEncode( /* int */ cipherIndex, /* int */ cipherModeIndex, /* int */ paddingIndex, /* int */ pad ) {
        /* Buffered word. */
        let buf = new Buffer( 4 );

        /* Target character set. */
        let subset = discordCrypt.getUtf16();

        /* Base64-Character set. */
        let original = discordCrypt.getBase64();

        let result = "", msg;

        /* Parse the first 8 bits. */
        if ( typeof cipherIndex === 'string' )
            cipherIndex = discordCrypt.cipherStringToIndex( cipherIndex );
        buf[ 0 ] = cipherIndex;

        /* Parse the next 8 bits. */
        if ( typeof cipherModeIndex === 'string' )
            cipherModeIndex = [ 'cbc', 'cfb', 'ofb' ].indexOf( cipherModeIndex.toLowerCase() );
        buf[ 1 ] = cipherModeIndex;

        /* Parse the next 8 bits. */
        if ( typeof paddingIndex === 'string' )
            paddingIndex = [ 'pkc7', 'ans2', 'iso1', 'iso9', 'zr0' ].indexOf( paddingIndex.toLowerCase() );
        buf[ 2 ] = paddingIndex;

        /* Add padding. */
        pad = parseInt( pad );
        buf[ 3 ] = pad;

        /* Convert to Base64. */
        msg = buf.toString( 'base64' );

        /* Calculate the target character. */
        for ( let i = 0; i < msg.length; i++ )
            result += subset[ original.indexOf( msg[ i ] ) ];

        return result;
    }

    /* Decodes an input string and returns a byte array containing index number of options. */
    static metaDataDecode( /* string */ message ) {
        /* Target character set. */
        let subset = discordCrypt.getUtf16();

        /* Base64-Character set. */
        let original = discordCrypt.getBase64();

        let result = "", msg, buf;

        /* Strip the extra UTF16 character then decode the message */
        msg = message.split( '' ).join( '' );

        /* Calculate the target character. */
        for ( let i = 0; i < msg.length; i++ )
            result += original[ subset.indexOf( msg[ i ] ) ];

        /* Convert from base64. */
        buf = atob( result );

        return [
            buf[ 0 ].charCodeAt( 0 ),
            buf[ 1 ].charCodeAt( 0 ),
            buf[ 2 ].charCodeAt( 0 ),
            buf[ 3 ].charCodeAt( 0 )
        ];
    }

    /* Encrypts a message using a symmetric key. */
    static symmetricEncrypt(
        /* string|Buffer|Array */    message,
        /* string|Buffer|Array */    primary_key,
        /* string|Buffer|Array */    secondary_key,
        /* int */                    cipher_index,
        /* int */                    block_mode,
        /* int */                    padding_mode,
        /* boolean */                use_hmac
    ) {

        /* Performs one of the 5 standard encryption algorithms on the plain text. */
        function handleEncodeSegment(
            /* string|Buffer|Array */   message,
            /* string|Buffer|Array */   key,
            /* int */                   cipher,
            /* string */                mode,
            /* string */                pad
        ) {
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
                use_hmac,
                false
            );
        else if ( cipher_index >= 5 && cipher_index <= 9 )
            msg = discordCrypt.aes256_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 5, mode, pad ),
                secondary_key,
                mode,
                pad,
                use_hmac,
                false
            );
        else if ( cipher_index >= 10 && cipher_index <= 14 )
            msg = discordCrypt.camellia256_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 10, mode, pad ),
                secondary_key,
                mode,
                pad,
                use_hmac,
                false
            );
        else if ( cipher_index >= 15 && cipher_index <= 19 )
            msg = discordCrypt.idea128_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 15, mode, pad ),
                secondary_key,
                mode,
                pad,
                use_hmac,
                false
            );
        else if ( cipher_index >= 20 && cipher_index <= 24 )
            msg = discordCrypt.tripledes192_encrypt(
                handleEncodeSegment( message, primary_key, cipher_index - 20, mode, pad ),
                secondary_key,
                mode,
                pad,
                use_hmac,
                false
            );

        /* If using HMAC mode, compute the HMAC of the ciphertext and prepend it. */
        if ( use_hmac ) {
            /* Get MAC tag as a hex string. */
            let tag = discordCrypt.hmac_sha256( new Buffer( msg, 'hex' ), primary_key, true );

            /* Prepend the authentication tag hex string & convert it to Base64. */
            msg = new Buffer( tag + msg, 'hex' ).toString( 'base64' );
        }

        /* Return the message. */
        return discordCrypt.substituteMessage( msg, true );
    }

    /* Decrypts a message using a symmetric key. */
    static symmetricDecrypt(
        /* string */    message,
        /* string */    primary_key,
        /* string */    secondary_key,
        /* int */       cipher_index,
        /* int */       block_mode,
        /* int */       padding_mode,
        /* boolean */   use_hmac
    ) {
        const crypto = require( 'crypto' );

        /* Performs one of the 5 standard decryption algorithms on the plain text. */
        function handleDecodeSegment(
            /* string|Buffer|Array */ message,
            /* string|Buffer|Array */ key,
            /* int */                 cipher,
            /* string */              mode,
            /* string */              pad,
            /* string */              output_format = 'utf8',
            /* boolean */             is_message_hex = undefined
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
        if ( block_mode === 0 )
            mode = 'cbc';
        else if ( block_mode === 1 )
            mode = 'cfb';
        else if ( block_mode === 2 )
            mode = 'ofb';
        else return '';

        /* Convert the padding. */
        if ( padding_mode === 0 )
            pad = 'pkc7';
        else if ( padding_mode === 1 )
            pad = 'ans2';
        else if ( padding_mode === 2 )
            pad = 'iso1';
        else if ( padding_mode === 3 )
            pad = 'iso9';
        else if ( padding_mode === 4 )
            pad = 'zr0';
        else return '';

        try {
            /* Decode level-1 message. */
            message = discordCrypt.substituteMessage( message );

            /* If using HMAC, strip off the HMAC and compare it before proceeding. */
            if ( use_hmac ) {
                /* Convert to a Buffer. */
                message = new Buffer( message, 'base64' );

                /* Pull off the first 32 bytes as a buffer. */
                let tag = new Buffer( message.subarray( 0, 32 ) );

                /* Strip off the authentication tag. */
                message = new Buffer( message.subarray( 32 ) );

                /* Compute the HMAC-SHA-256 of the cipher text as hex. */
                let computed_tag = new Buffer( discordCrypt.hmac_sha256( message, primary_key, true ), 'hex' );

                /* Compare the tag for validity. */
                if ( !crypto.timingSafeEqual( computed_tag, tag ) )
                    return 1;
            }

            /* Dual decrypt the segment. */
            if ( cipher_index >= 0 && cipher_index <= 4 )
                return handleDecodeSegment(
                    discordCrypt.blowfish512_decrypt( message, secondary_key, mode, pad, 'base64', use_hmac ),
                    primary_key,
                    cipher_index,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 5 && cipher_index <= 9 )
                return handleDecodeSegment(
                    discordCrypt.aes256_decrypt( message, secondary_key, mode, pad, 'base64', use_hmac ),
                    primary_key,
                    cipher_index - 5,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 10 && cipher_index <= 14 )
                return handleDecodeSegment(
                    discordCrypt.camellia256_decrypt( message, secondary_key, mode, pad, 'base64', use_hmac ),
                    primary_key,
                    cipher_index - 10,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 15 && cipher_index <= 19 )
                return handleDecodeSegment(
                    discordCrypt.idea128_decrypt( message, secondary_key, mode, pad, 'base64', use_hmac ),
                    primary_key,
                    cipher_index - 15,
                    mode,
                    pad,
                    'utf8',
                    false
                );
            else if ( cipher_index >= 20 && cipher_index <= 24 )
                return handleDecodeSegment(
                    discordCrypt.tripledes192_decrypt( message, secondary_key, mode, pad, 'base64', use_hmac ),
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
module.exports = discordCrypt;
