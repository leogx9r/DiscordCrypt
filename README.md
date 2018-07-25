<h1 align="center">
    <img src="https://assets.gitlab-static.net/uploads/-/system/project/avatar/6431320/discordCrypt-mini.png" height="50" width="50">
    DiscordCrypt <h3>End-To-End File & Message Encryption For Discord</h3>
</h1>

* [**Features**](#features)
* [**Introduction**](#introduction)
* [**Verifying Signatures**](#verifying-signatures)
* [**Installation**](#installation)
    * [***Windows***](#windows)
    * [***MacOS***](#macos)
    * [***Linux***](#linux)
* [**Usage**](#usage)
    * [***Creating A New Database***](#creating-a-new-database)
    * [***Changing The Database Password***](#changing-the-database-password)
    * [***Exchanging Keys***](#exchanging-keys)
        * [*Personal Conversations*](#personal-conversations)
        * [*Group Conversations And Channels*](#group-conversations-and-channels)
            * [*Alternative Method*](#alternative-method)
    * [***Resetting Or Updating Conversation Passwords 
        Manually***](#resetting-or-updating-conversation-passwords-manually)
* [**Best Practices**](#best-practices)
* [**Debugging**](#debugging)
* [**Frequently Asked Questions ( FAQs )**](#frequently-asked-questions)
* [**Known Limitations And Bugs**](#known-limitations-and-bugs)
* [**Support And Discussion**](#support-and-discussion)

 

# Features
 
* Supports Windows, MAC and Linux.
* All messages are encrypted using the most secure methods available.
* Emojis ( Animated, Nitro ) are supported even if you're not a nitro user.
* Encrypted database with a password of your choosing protects all passwords.
* Supports timed messages which are removed after a set period.
* Ability to backup and restore all passwords.
* Dual encryption mode with multiple ciphers supported.
* Strong key exchange for easily exchanging keys.
* Supports encrypted file uploads up to 50 MB.
* File uploads are automatically deleted after 7 days.
* Supports embedded encrypted messages or normal messages.
* Automatic updates to ensure you always get the latest features.
* Updates are manually verified to ensure authenticity.
* Designed to provide the maximum security and privacy.
* Extensively tested for reliability and stability.

# Introduction

![Encrypted Message](images/encrypted-message.png)

**DiscordCrypt** is a plugin for Discord that uses BetterDiscord's internal structure to send and 
    receive encrypted messages between users and channels in a safe and secure manner.

The plugin achieves this by using 
    [multiple levels of encryption](https://en.wikipedia.org/wiki/Multiple_encryption) 
    with well known ciphers to ensure only the people you want to read your messages can read them 
    and ***no one else***.

The source code is completely free and open source 
    ( [**FOSS**](https://en.wikipedia.org/wiki/Free_and_open-source_software) ) and licensed under 
    the [**MIT License**](LICENSE) so feel free to have a look or modify it as you see fit!

If you'd like an in-depth explanation of its inner workings, click [here](TECHNICALITIES.md).

If you wish to use a web browser instead of Discord's native application, we recommend you use 
    [**SimpleDiscordCrypt**](https://gitlab.com/An0/SimpleDiscordCrypt) made by our friend An0.
    Please note, these two versions are incompatible with one another.

Contributions are welcome! Be sure to read [our guidelines](CONTRIBUTING.md) before submitting 
    your changes.

Also, while this project is licensed under the MIT, if you feel generous and wish to buy the 
    creators coffee, we'll happily accept.


| **Name**     | **Address**                                                                                        |
| ------------ | -------------------------------------------------------------------------------------------------- |
| Bitcoin      | `1NYCgcr6JXkX5TZUJcjQYJmeuPxBQ48tTo`                                                               |
| Bitcoin Cash | `qrscw5y3h478whz2zd6fluacmadmkrdca5zghfsw23`                                                       |
| Ethereum     | `0x36e89B89f565C6F5E36988Ee5B7DC00cC4Bfda31`                                                       |
| Monero       | `83h2PKvpjx9dDK1VJ5B2h8ADbZZUcfEbwaQqqve8nmWv3VyvY7tNv5FLa3dUPwybJGZoGWCz5UDjfDYmKttQmChV2Wv9uiq`  |


 

# Verifying Signatures

For every release starting with version 
    [`1.2.4`](https://gitlab.com/leogx9r/DiscordCrypt/tags/v1.2.4), 
    we [sign](https://www.gnupg.org/gph/en/manual/x135.html) the plugin using 
    [GPG](https://en.wikipedia.org/wiki/GNU_Privacy_Guard) for increased security.
 
***You should ALWAYS verify the signature of this plugin before using it to ensure it has 
    not been maliciously tampered with.***

For Windows and Linux operating systems, we recommend you use 
    [`Kleopatra`](https://www.openpgp.org/software/kleopatra/) for verifying signatures and for 
    MacOS, we recommend [`GnuPG for OS X`](https://gnupg.org/download/index.html).

The signature for each release is located [here](build/discordCrypt.plugin.js.sig). 
    Please read the manual for your specific client to determine how to verify signatures.

If everything goes well, you'll notice output similar to below:

```
$ gpg --verify build/discordCrypt.plugin.js.sig
gpg: assuming signed data in `build/discordCrypt.plugin.js'
gpg: Signature made Fri 1 Jun 2018 00:00:01 AM 00 using RSA key ID 3787CE3F
gpg: Good signature from "DiscordCrypt (DiscordCrypt Signing Key)"
```

The above depends on the client you use but you must always look for a 
    "*Good*", "*OK*" or "*Valid*" signature.

Please note, you will need to import the signing key located [here](build/signing-key.pub) 
    to verify signatures.

Finally, you should manually verify that the signing key you import above matches the 
    information below:

```
Key ID: 3787CE3F 
Fingerprint: B8EC 0775 960A EB2E 4C11 F084 DA61 3E75 3787 CE3F 
```

**N.B** The plugin self-verifies every update so you only ever need to verify these 
    signatures once upon your first installation.


 

# Installation

**DiscordCrypt** is installed just like any other 
    [BetterDiscord](https://github.com/rauenzi/BetterDiscordApp/releases) plugin. 
    If you do not have BetterDiscord installed, be sure to do that first before continuing with 
    this guide.

**N.B** For now, the plugin has ***only*** been tested on *Windows* and *Linux* but it 
    should work for all operating systems that support BetterDiscord.

For installation on specific operating systems, see below:

 

#### Windows

* [Download](https://gitlab.com/leogx9r/DiscordCrypt/raw/master/build/discordCrypt.plugin.js) 
    the plugin file. ( Right Click -> Save As )
* Save the plugin to the following path: **`%APPDATA%\BetterDiscord\plugins`**.
    * *Example: `C:\Users\Jeremy\AppData\Local\BetterDiscord\plugins\discordCrypt.plugin.js`*
* **Ensure** the file is named exactly as **`discordCrypt.plugin.js`**.
* Restart Discord by pressing: **`Ctrl + R`**.
* Enable the plugin in BetterDiscord's plugin settings menu.

 

#### MacOS

* [Download](https://gitlab.com/leogx9r/DiscordCrypt/raw/master/build/discordCrypt.plugin.js) 
    the plugin file. ( Right Click -> Save As )
* Save the plugin to the following path: **`~/Library/Preferences/BetterDiscord/plugins`**.
    * *Example: `/home/jeremy/Library/Preferences/BetterDiscord/plugins/discordCrypt.plugin.js`*
* **Ensure** the file is named exactly as **`discordCrypt.plugin.js`**.
* Restart Discord by pressing: **`Ctrl + R`**.
* Enable the plugin in BetterDiscord's plugin settings menu.

 

#### Linux

*The following instructions are for **Discord Stable/Canary***.
( Get it [here](https://discordapp.com/api/download?platform=linux&format=deb) for Debian/Ubuntu. )

The *PTB* or *SNAP* versions have **NOT** been tested.

* [Download](https://gitlab.com/leogx9r/DiscordCrypt/raw/master/build/discordCrypt.plugin.js) 
    the plugin file. ( Right Click -> Save As )
* Save the plugin to the following path: **`~/.config/BetterDiscord/plugins`**.
    * *Example: `/home/jeremy/.config/BetterDiscord/plugins/discordCrypt.plugin.js`*
    * If you use another version of Discord, install it to the designated BetterDiscord 
        plugin path for your version.
* **Ensure** the file is named exactly as **`discordCrypt.plugin.js`**.
* Restart Discord by pressing: **`Ctrl + R`**.
* Enable the plugin in BetterDiscord's plugin settings menu.

 

# Usage

**DiscordCrypt** creates a menu bar upon loading, allowing you to interact with the plugin.

---

![Menu Bar](images/menu-bar.png)

---

These icons each offer a different functionality as follows:

* **[1] Upload Encrypted Clipboard**
    * This uploads your current clipboard to the Up1 file service and sends an encrypted link 
        to the file to the current channel.
    * After uploading, this sets your clipboard to the deletion link for the uploaded file which 
        you may use to either manually delete the file after your colleague has downloaded it 
        or for later deletion.
    * You are limited to a maximum of 50 MB just as the standard file upload.    
* **[2] Upload Encrypted File**
    * This opens the file upload menu that you may use to encrypt and upload a file less than 
        50 MB to an Up1 service.
    * You may choose whether to randomize the file name and whether to attach a deletion link 
        to the message.
    * You are also able to write a message prior to sending the file which will be sent immediately.
        * Standard message limits apply. Messages longer than the maximum length will be split 
            into multiple messages.
    * Files are encrypted using *AES-256* in [CCM](https://en.wikipedia.org/wiki/CCM_mode) mode 
        as per Up1's protocol.
* **[3] Plugin Settings**
    * This menu controls the settings for the plugin.
    * You can enable and disable each option here.
    * This also contains a database management menu allowing you to import and export your current 
        passwords.
        * Note that exported entries are **NOT ENCRYPTED** and as such should be handled 
            with caution.
* **[4] Enable/Disable Message Encryption**
    * Clicking this button either enables or disables automatic encryption.
    * Automatic encryption will always encrypt any message sent if passwords are defined for the 
        current channel.
    * Clicking this button changes the lock icon to an unlock icon indicating messages sent will 
        not be automatically encrypted.
        * Clicking this icon again re-enables automatic encryption and changes the lock icon back 
            to the default seen above.
* **[5] Password Settings**
    * This menu allows you to set, change, reset or copy the passwords applied to the 
        current channel.
    * If you reset the current passwords, they will use the default passwords defined in 
        `Plugin Settings`.
    * Using the `Copy Current Passwords` button to the clipboard for sharing.
* **[6] Key Exchange Menu**
    * This allows you to manually generate and send public keys to your colleges.
    * This is also the menu responsible for performing key exchanges.
    * This is further detailed below.
* **[7] Generate & Send New Public Key**
    * This simplifies the key exchanging process by manually generating and sending a new 
        public key to your current channel.
    * This generates a public key according to the current algorithm and bit length defined in 
        the `Key Exchange Menu`.
    * This is further detailed below.

 

### Creating a new database

Every time Discord starts, you will be met with a prompt seen below:

---

![Greeting Prompt](images/greeting-prompt.png)

---

**DiscordCrypt** uses an AES-256 encrypted database file in 
    [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) mode to store its information and 
    uses a ***master password*** to unlock this file.

The first time you use the plugin, you'll be prompted to input a new password that will 
    be used to create the database.

Every additional time you start or restart Discord, you'll be prompted with the above screen 
    where you must enter the same password as before. If you don't enter the same password,
    you will not be able to unlock your database and decrypt any messages.

All exchanged keys and passwords are saved to this database and **cannot be recovered** 
    if the master password is lost so be sure to use a strong but memorable one. 
    ( [Forgot Password?](#forgotten-master-password) )

**N.B. This password is the only thing protecting all others and as such, should be a very 
    strong and unpredictable.**
 

### Changing the database password

If you wish to change your master password, you may do so in the `DiscordCrypt Settings` menu.
    ![settings](images/settings-menu.png)

You can only do this however, after you unlock the database with your previous password.

If you enter a password in the `New Master Database Password` field and save your settings, 
    this key will be used to encrypt the database in the future.

![masterpassword](images/master-password.png)

**N.B.** If a key is not entered into this field, it is ignored. Your current password will 
    **NOT** be replaced.

 

### Exchanging Keys


While we give users a choice regarding the options they want to use when originally setting up 
    an encrypted conversation via manually setting passwords, we offer a simple way to do it, 
    using strong cryptography.

This involves using an 
[asymmetric key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) 
    algorithm which, while allowing you to post information on an insecure channel, allows a 
    strong secret key to be shared between two parties.

Advanced users are free to mess with the configuration, though be aware that we will only 
    discuss the built-in key exchange feature in this tutorial.

 

#### Personal Conversations

###### Short Explanation

All it takes is three ( 3 ) clicks.

* Generate a key and send a new public key using the Auto-Key-Exchange button. 
    ( ![s1](images/auto-handshake.png) )
    * You may skip this step if your partner is generating their key first. Hooray, down 
        to two ( 2 ) clicks!
* Once your partner's public key appears, click the `Perform Key Exchange` button in the 
    message that just appeared at the bottom of the message.
* After the passwords are generated and the progress bar fully fills, click the 
    `Apply Generated Passwords` button located at the bottom of the pop-up window.

 

###### Longer Explanation

* Go in the channel or conversation you want to set a password for.
* If you're not sure whether you've sent a key before, go to the `Key Exchange` menu 
    ( ![1](images/key-exchange.png) ) and then to the `Key Generation` tab.
    * If both fields are empty, exit the Key Exchange menu by pressing the `[X]` on the top right 
        ( ![2](images/close-menu.png) ).
    * If both fields are full of numbers and letters, clicks the `Clear` button, then exit the menu.
* If you're initiating the key exchange, click on `Generate & Send New Public Key` 
    ( ![3](images/auto-handshake.png) ) and wait until a public key 
    [is sent in the chat](images/public-key-message.png).
* If your friend is initiating the key exchange, simply wait until you see his key appear 
    in the chat, then click `Perform Key Exchange`.
    * If you've initiated the exchange, you also need to click this button after your friend 
        has ( automatically ) shared their key.
* Once this is done, you should see a window pop up after a few seconds, with a progress bar 
    at the bottom.
* Wait until both passwords are generated, then click `Apply Generated Passwords`.

Voila, your conversation will now be encrypted using keys you've just created.

 

#### Group Conversations And Channels

Exchanging keys for a group conversation or a channel is a longer process and a bit more complex.

You may want to leave your group chat unencrypted if you don't discuss anything sensitive.

The process, however, is quite similar to generating keys for a personal conversation.

* First you must decide who in the group will generate keys with you. 
* Then, you must follow the same steps as if you were generating passwords for a personal 
    conversation, except you need to stop before clicking `Apply Generated Passwords`.
* Once you've generated both passwords, you need to copy them using the `Copy Keys & Nuke` button.
* Open up notepad or your preferred text editor and paste the passwords for later use.
* As you should only share the passwords securely, you need to exchange keys with every member 
    of the channel/group.
    * This means you must create an encrypted, 1-on-1 conversation with every members and 
        share the passwords.
* Once you've created a secure channel with every members, individually, you can send the 
    passwords in an encrypted message. 
* After the passwords have been shared ( securely ), every user must manually set the 
    passwords for the channel. ( More on that below. )

 

###### Alternative Method

There is an alternative process for sharing existing passwords with users but it is 
    **highly** ***unrecommended***.

* Switch to the group or channel that currently uses encrypted messages.
* Open the `Password Settings` menu. ( ![5](images/password-menu.png) )
* Click on `Copy Current Passwords` located at the bottom of the panel.
    * Please note this copies the keys from your current channel in an **UNENCRYPTED** 
        form to your clipboard.
    * **KEEP THEM SAFE AND DO NOT SAVE THEM**.
* Paste your clipboard to your partner over an encrypted channel. 
    ( `Ctrl+V` or `Right Click -> Paste` )

 

### Resetting Or Updating Conversation Passwords Manually

You may one day end up in a situation where you need to manually reset or update the 
    password for the current conversation.

One such situation is when sharing keys for group conversations. If this is the case, 
    use this method.

**N.B. We recommend against manually creating a password as we offer a tool to securely 
    generate strong passwords for both parties.**

If it comes to this, you simply need to go to the `Password Settings` menu 
    ( ![6](images/password-menu.png) ) to apply your passwords.

If you are manually updating the passwords to be able to have an encrypted group 
    conversation, simply paste the "Primary Key" in the first field and the 
    "Secondary Key" in the second field, then press `Save Password`.

 

# Best Practices

The following tips should be adhered to for maximum privacy between users.

* Change your master database password frequently.
* **NEVER** share passwords across unencrypted communications. Always establish a secure 
    connection by means of a key exchange before sending passwords.
* Change your message keys on a frequent basis. This ensures that even if your current 
    keys are compromised that an attacker will not be able to read any future messages.
* Use large key sizes ( preferably the maximum ) when exchanging keys. For Diffie-Hellman, 
    this is 8192 bits or for Elliptic Curve Diffie-Hellman, this is 521/571 bits.
* Use strong passwords for encrypting your database. Passwords **should be at least 
    8 characters long and contain a combination of alphanumeric ( ***A-Z***, ***0-9*** ) 
    and symbolic characters**.
    * We recommend using a [password manager](https://en.wikipedia.org/wiki/Password_manager) 
        such as [KeePassX](https://www.keepassx.org/)/[KeePassXC](https://keepassxc.org/), 
        [OnePass](https://masterpassword.app/) or [LastPass](https://www.lastpass.com) 
        to generate and safely store strong passwords though we strongly prefer the 
        KeePass app variants ourselves.
* Use AES as either the primary or secondary ciphers for encryption. AES is a cipher 
    developed in 1998 and is still considered one of the most secure methods of 
    sending and receiving confidential information to this day.
* If you require absolute secrecy which is not vulnerable to Discord's potential 
    MiTM attacks, use a strong password generator, encrypt these using PGP and 
    send them to your partner over a non-Discord channel then manually apply these
    keys after you decrypt them.

 

# Debugging

The official Discord client is built with the [Electron framework](https://electronjs.org) 
    that uses a tweaked Chromium version bundled with [Node.js](https://nodejs.org/en/) 
    support.

The DevTools console interface can be opened using the key combination of: `Ctrl + Shift + I`.

In the event that you encounter an error and wish to submit an issue to us to help 
    resolve this problem, please follow these steps:

* First ensure you disabled all themes and plugins to 
    [avoid possible incompatibilities](https://gitlab.com/leogx9r/DiscordCrypt/issues/5).
* Download and drop the `discordCrypt.plugin.js` into your BetterDiscord Plugins folder.
    Restart Discord afterwards. ( `Ctrl + R` )
* Exactly like on Chromium, you can open the debug console by pressing `Ctrl + Shift + I`.
* Watch your console while using the client as you would normally do. In the the opened 
    debug console window switch to the 'Console' tab and see if there are any errors. 

In case there is an error caused by the plugin, create an issue ticket with the 
    exact debug output. You should, as a general practice of security, strip any 
    identifiable information from your request. If however more information is 
    required than you provided, we'll request it from you.

Be sure to read the [contribution](CONTRIBUTING.md) guidelines before creating an issue.

 

# Frequently Asked Questions

### Isn't Discord already encrypted or private ?

Discord ***claims*** that all its messages are encrypted, and while that 
    **is** true ***to an extent*** as they are sent over an HTTPS connection, 
    it ***does NOT mean that they cannot see the content*** of your messages.

For anyone concerned about or valuing their right to privacy, this is an unfortunate 
    caveat of using Discord. 

Messages sent to your friends or servers are encrypted before they're sent out but 
    are decrypted by Discord's servers.

This means anything you've ever sent, typed, or spoken could have been recorded and 
    logged by Discord's owners.

Various messenger applications ( Signal, Riot etc. ) have taken user's privacy seriously 
    and implemented [end-to-end encryption](https://en.wikipedia.org/wiki/End-to-end_encryption) 
    so that no one, not even the platform's owners, can see what users do.

Discord has declined several suggestions to implement end-to-end encryption in the past and 
    also constantly attempt to control what users can do or say by censoring users or group 
    chats that they otherwise do not agree with.
     
We do not mean to say that hate-speech, racism or other morally wrong topics are okay 
    but rather it violates free-speech when Discord themselves are given the right to choose 
    what can and cannot be said by users.
    
In addition to this, Discord's current CEO, [Jason Citron](https://twitter.com/jasoncitron) 
    previously founded another application quite similar to Discord, 
    [OpenFeint](https://en.wikipedia.org/wiki/OpenFeint) which had been caught harvesting and 
    [illegally selling user data](https://courthousenews.com/gamers-say-openfeint-sold-them-out) 
    to advertisers for profit which has since been shut down shortly after a class-action lawsuit 
    was filed against them.

This also includes the fact
    that their system actively tracks users, their messages which they refuse to delete and 
    generally, have been caught doing sneaky things in the past. See 
    [here](https://tomsguide.com/us/help-me-toms-guide-discord-permissions,review-5104.html).

    The OpenFeint mobile gaming network collected data and personal information from its 
    users’ cellphone-linked profiles and sold the information to Internet application developers, 
    according to a federal class action.
    
    Lead plaintiff Matthew Hines claims Openfeint accessed, monitored and stored the unique 
    device identifiers for mobile devices along with personally identifiable information such 
    as a user’s exact GPS location, Internet browsing history and Facebook and Twitter profiles.
    
    OpenFeint’s business plan included accessing and disclosing personal information without 
    authorization to mobile-device application developers, advertising networks and web-analytic 
    vendors that market mobile applications, according to the complaint. 
    
    The company acquired such information covertly, without adequate notice or consent, 
    involving 100 million consumer mobile devices.

    After accessing one of OpenFeint’s applications, the company bypassed both the technical 
    and code barriers designed to limit unauthorized access, as well as his mobile device’s 
    privacy and security settings, Hines claims.
    
    OpenFeint used the data it collected to collaborate with application developers and create 
    a database that further enabled the tracking scheme and conducted systematic and continuing 
    surveillance of the class members’ mobile-device activity, which continues today.
    
    In spite of this activity, OpenFeint assures customers that its applications are all safe for 
    downloading, according to the suit.
    
For visual proof of this, please see:

* [Initial E2E Request Denied](images/discord-end-to-end-denied.png)
* [Refusal For User Data Deletion](images/discord-refuses-to-delete-user-data.png)
* [Government Requests For User Data](images/discord-requests-for-user-data.png)

We highly disapprove of their ideals as we believe their actions violate every human's 
    right to privacy.

This plugin attempts to implement the behavior of end-to-end encryption behavior so you 
    can actually keep your messages between friends private.

While this plugin does not support, nor plan to support end-to-end voice encryption, 
    messages and uploaded files via the encrypted file uploading interface **should** 
    be safe and secure from prying eyes.

 

### Unattractive UI

Unfortunately, the core project members have never been good CSS designers as we 
    mainly specialize in internal application and system-level programming.

If you however do know how to make an attractive UI, please do create a pull request 
    with your changes!

 

### Tagging Users

As we explained in the [Known Limitations](#known-limitations-and-bugs), tagging users 
    normally does not work because we cannot notify users of tags after messages 
    have been decrypted.

We created a workaround for this allowing you to notify whoever you want while still 
    benefiting from encrypted messages.

The idea behind this is simple:

When you tag users in a message, **DiscordCrypt** will extract the usernames and send 
    them in an unencrypted form while the rest of the message is encrypted.
    
Prior to sending, messages will have the user's discriminator removed from the message.

This way, you can send notifications to tagged users while leaving the original username(s) in 
    the message intact so as to not lose context.


***Be aware that the mentions will display a user's "nickname" on the server,
    while the embed will retain the original name meaning even though the content of your 
    message is encrypted, onlookers will still be able to know who the message is intended 
    for.***

Here's how this looks:

![User Tagging](images/tags.png)


 

### Skipping Startup Screen

The screen prompting you to unlock your database is necessary for **DiscordCrypt** to 
    function. Without it, you won't be able to send or receive any encrypted messages.

If you wish to stop seeing it, you will simply have to disable the plugin optionally, 
    click the `Cancel` button to bypass this prompt.

 

### Forgotten Master Password

You can reset your database ( and thus your configuration ) by deleting the file 
    `DiscordCrypt.config.json` located in the same directory as the plugin that you went to 
    during [installation](#installation).

Doing this will reset your configuration and allow you to enter a new password. 
    Be aware that by resetting your configuration, you will lose the passwords of all of 
    your encrypted conversations.

As a result, you will need need to perform a new key exchange with your friends. 
    If you're part of an encrypted group/channel conversation, you will need to generate 
    new keys or ask someone to send your the passwords securely.

 

### Sharing Passwords With New People

While we do not recommend sharing passwords with newcomers, and instead suggest you generate 
    new keys whenever that happens, you can copy the passwords of the current channel and 
    share them by following [theses steps](#alternative-method).

 

### DiscordCrypt CPU Usage

Unless you're generating keys or performing encrypted file uploads, **DiscordCrypt** should not 
    be CPU heavy.

Discord itself can be annoying in that regard as it generally uses a large amount of processing 
    power.

If you believe it is causing issues, you may want to try increasing the 
    `Encryption Scanning Frequency` in the plugin settings.

 

### This Is Complicated

Unfortunately, implementing privacy and message encryption in this manner is difficult to do.

We've tried to simplify the process as much as possible but once you get used to it, it becomes 
    much easier.

 

### Why Embedded Messages

We wanted a way for users who both use and do not use the plugin to easily identify 
    encrypted messages.

In addition to this, rich embeds provide a nicer means of conveying and formatting the 
    encrypted messages that standard messages do not as well as making the plugin itself 
    detect encrypted messages easily.

We however do support non-embedded messages as a means to avoid users having their embed 
    permissions revoked and possibly have their account disabled however it does not offer 
    the same look or feel that standard encrypted messages do.

By default, the plugin will NOT use embeds and warns users about this in the settings menu.

 

# Known Limitations And Bugs

**DiscordCrypt** is not ( and sadly cannot be ) perfect, the plugin is limited in the number 
    of features it can provide.

Some of **DiscordCrypt**'s limitations are due to the fact that decrypted messages cannot 
    undergo the standard post-processing that Discord itself does. An example of this would be 
    link previews.

 

* ***DiscordCrypt's key exchange is vulnerable to Discord's servers being used for 
    [Man-in-The-Middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack).***
    * While an attacker would need access to Discord's infrastructure as the data is 
        encrypted in transit using TLS, it is in theory possible for an attacker, 
        the government or Discord's administrators to sit in the middle of the 
        key exchange.
        * We discussed this in greater details in the [TECHNICALITIES.md](TECHNICALITIES.md) file.



* Messages are limited to 1820 characters each.
    * Due to additional costs of encryption, messages at maximum size will only be able to 
        display 1820 characters of text..
        * If your message is longer than this, it will be split and sent in multiple messages.
 


* Only text channels are end-to-end encrypted. Voice channels cannot be secured, so what you 
    verbally say in them could still be recorded by Discord.
    * Support for encrypted file uploads was added in `v1.0.5`. However we still recommend using 
        [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) to encrypt especially sensitive 
        files before sending them.



* Tagging users works in a different way when using encrypted messages:
    * As we use embeds, tagging users in a message should result in them not being notified.
        * To fix this, every users tagged in a message will receive an unencrypted notification.
            [Example here](#tagging-users).



* Searching past messages is impossible.
    * Since messages are encrypted and the search feature relies 
        on the ability for Discord's servers to read past messages, the search functionality will 
        always be unavailable.
    * If you require searching, you may send your messages in an unencrypted format by making 
        them start with the hash ( `#` ) character.
    * Messages also will be sent unencrypted if they begin with the forward-slash ( `/` ) character 
        as these are also used for commands.
 


* Some third-party plugins may conflict with **DiscordCrypt**.
    * One such example discovered so far is the plugin `OldTitleBar` by DevilBro. This plugin 
        causes **DiscordCrypt**'s icons to be unclickable.
        * We do not plan to fix this, but feel free to contribute if you wish to do so yourself.
        * For a list of known problematic themes and plugins, see
            [here](https://gitlab.com/leogx9r/DiscordCrypt/issues/5).

 

# Support And Discussion

If you've discovered a bug in the plugin, feel free to create an issue after reading the 
    [contribution guide](CONTRIBUTING.md). Please be as detailed as possible when submitting 
    your issues.

We also have a [Discord Server](https://discord.me/discordcrypt) for any discussion 
    related to **DiscordCrypt** and for general support.

 
