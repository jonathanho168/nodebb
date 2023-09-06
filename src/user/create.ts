import zxcvbn = require('zxcvbn');
import winston = require('winston');

import db = require('../database');
import utils = require('../utils');
import slugify = require('../slugify');
import plugins = require('../plugins');
import groups = require('../groups');
import meta = require('../meta');
import analytics = require('../analytics');

interface UserData {
    username: string;
    userslug: string;
    accounttype?: string;
    email?: string;
    joindate: number;
    lastonline: number;
    status: string;
    picture?: string;
    fullname?: string;
    location?: string;
    birthday?: string;
    gdpr_consent?: number;
    acceptTos?: number;
    uid?: number;
}

interface CreationData extends Partial<UserData> {
    timestamp?: number;
    'account-type'?: string;
    password?: string;
    gdpr_consent?: boolean;
    acceptTos?: boolean;
}

type UserMethods = {
    create: (data: any) => Promise<number>;
    isDataValid: (userData: any) => Promise<void>;
    isPasswordValid: (password: string, minStrength?: number) => void;
    uniqueUsername: (userData: any) => Promise<string | null>;
    notifications: any;
    updateDigestSetting: any;
    email: any;
    hashPassword: any;
    setUserFields: any;
    reset: any;
    
};

export default function (User : UserMethods) : void {
    User.create = async function (data : CreationData) : Promise<number> {
        data.username = data.username.trim();
        data.userslug = slugify(data.username);
        if (data.email !== undefined) {
            data.email = String(data.email).trim();
        }
        if (data['account-type'] !== undefined) {
            data.accounttype = data['account-type'].trim();
        }

        await User.isDataValid(data);

        await lock(data.username, '[[error:username-taken]]');
        if (data.email && data.email !== data.username) {
            await lock(data.email, '[[error:email-taken]]');
        }

        try {
            return await create(data);
        } finally {
            await db.deleteObjectFields('locks', [data.username, data.email]);
        }
    };

    async function lock(value : string, error : string) {
        const count = await db.incrObjectField('locks', value);
        if (count > 1) {
            throw new Error(error);
        }
    }

    async function create(data : CreationData) : Promise<number> {
        const timestamp = data.timestamp || Date.now();

        let userData : UserData = {
            username: data.username,
            userslug: data.userslug,
            accounttype: data.accounttype || 'student',
            email: data.email || '',
            joindate: timestamp,
            lastonline: timestamp,
            status: 'online',
        };
        ['picture', 'fullname', 'location', 'birthday'].forEach((field) => {
            if (data[field]) {
                userData[field] = data[field];
            }
        });
        if (data.gdpr_consent === true) {
            userData.gdpr_consent = 1;
        }
        if (data.acceptTos === true) {
            userData.acceptTos = 1;
        }

        const renamedUsername = await User.uniqueUsername(userData);
        const userNameChanged = !!renamedUsername;
        if (userNameChanged) {
            userData.username = renamedUsername;
            userData.userslug = slugify(renamedUsername);
        }

        const results = await plugins.hooks.fire('filter:user.create', { user: userData, data: data });
        userData = results.user;

        const uid = await db.incrObjectField('global', 'nextUid');
        const isFirstUser = uid === 1;
        userData.uid = uid;

        await db.setObject(`user:${uid}`, userData);

        const bulkAdd = [
            ['username:uid', userData.uid, userData.username],
            [`user:${userData.uid}:usernames`, timestamp, `${userData.username}:${timestamp}`],
            ['username:sorted', 0, `${userData.username.toLowerCase()}:${userData.uid}`],
            ['userslug:uid', userData.uid, userData.userslug],
            ['users:joindate', timestamp, userData.uid],
            ['users:online', timestamp, userData.uid],
            ['users:postcount', 0, userData.uid],
            ['users:reputation', 0, userData.uid],
        ];

        if (userData.fullname) {
            bulkAdd.push(['fullname:sorted', 0, `${userData.fullname.toLowerCase()}:${userData.uid}`]);
        }

        await Promise.all([
            db.incrObjectField('global', 'userCount'),
            analytics.increment('registrations'),
            db.sortedSetAddBulk(bulkAdd),
            groups.join(['registered-users', 'unverified-users'], userData.uid),
            User.notifications.sendWelcomeNotification(userData.uid),
            storePassword(userData.uid, data.password),
            User.updateDigestSetting(userData.uid, meta.config.dailyDigestFreq),
        ]);

        if (userData.email && isFirstUser) {
            await User.email.confirmByUid(userData.uid);
        }

        if (userData.email && userData.uid > 1) {
            await User.email.sendValidationEmail(userData.uid, {
                email: userData.email,
                template: 'welcome',
                subject: `[[email:welcome-to, ${meta.config.title || meta.config.browserTitle || 'NodeBB'}]]`,
            }).catch(err => winston.error(`[user.create] Validation email failed to send\n[emailer.send] ${err.stack}`));
        }
        if (userNameChanged) {
            await User.notifications.sendNameChangeNotification(userData.uid, userData.username);
        }
        plugins.hooks.fire('action:user.create', { user: userData, data: data });
        return userData.uid;
    }

    async function storePassword(uid : number, password : string): Promise<void> {
        if (!password) {
            return;
        }
        const hash = await User.hashPassword(password);
        await Promise.all([
            User.setUserFields(uid, {
                password: hash,
                'password:shaWrapped': 1,
            }),
            User.reset.updateExpiry(uid),
        ]);
    }

    User.isDataValid = async function (userData : CreationData): Promise<void> {
        if (userData.email && !utils.isEmailValid(userData.email)) {
            throw new Error('[[error:invalid-email]]');
        }

        if (!utils.isUserNameValid(userData.username) || !userData.userslug) {
            throw new Error(`[[error:invalid-username, ${userData.username}]]`);
        }

        if (userData.password) {
            User.isPasswordValid(userData.password);
        }

        if (userData.email) {
            const available = await User.email.available(userData.email);
            if (!available) {
                throw new Error('[[error:email-taken]]');
            }
        }
    };

    User.isPasswordValid = function (password : string, minStrength? : number) {
        minStrength = (minStrength || minStrength === 0) ? minStrength : meta.config.minimumPasswordStrength;

        // Sanity checks: Checks if defined and is string
        if (!password || !utils.isPasswordValid(password)) {
            throw new Error('[[error:invalid-password]]');
        }

        if (password.length < meta.config.minimumPasswordLength) {
            throw new Error('[[reset_password:password_too_short]]');
        }

        if (password.length > 512) {
            throw new Error('[[error:password-too-long]]');
        }

        const strength = zxcvbn(password);
        if (strength.score < minStrength) {
            throw new Error('[[user:weak_password]]');
        }
    };

    User.uniqueUsername = async function (userData : UserData): Promise<string | null> {
        let numTries = 0;
        let { username } = userData;
        while (true) {
            /* eslint-disable no-await-in-loop */
            const exists = await meta.userOrGroupExists(username);
            if (!exists) {
                return numTries ? username : null;
            }
            username = `${userData.username} ${numTries.toString(32)}`;
            numTries += 1;
        }
    };
};
