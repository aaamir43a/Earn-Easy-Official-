const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const crypto = require('crypto');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { createClient } = require('redis');
const { RedisStore } = require("rate-limit-redis");

try {
    const serviceAccountBase64 = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!serviceAccountBase64) {
        throw new Error("Firebase Service Account key not found in environment variables.");
    }
    const serviceAccountJson = Buffer.from(serviceAccountBase64, 'base64').toString('ascii');
    const serviceAccount = JSON.parse(serviceAccountJson);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin SDK initialized successfully.");
} catch (error) {
    console.error("Firebase Admin SDK Initialization Error:", error.message);
}

const db = admin.firestore();
const app = express();
app.use(cors());
app.use(express.json());
const redisClient = createClient({
    url: process.env.REDIS_URL
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));

(async () => {
    await redisClient.connect();
    console.log("Successfully connected to Redis.");
})();

const keyGenerator = (req) => {
    try {
        const authHeader = req.headers['x-telegram-auth'];
        if (!authHeader) {
            return crypto.randomUUID(); 
        }
        const initData = new URLSearchParams(authHeader);
        const user = JSON.parse(initData.get('user'));
        return user.id.toString();
    } catch (e) {
        return crypto.randomUUID();
    }
};

const generalLimiter = rateLimit({
    store: new RedisStore({
        sendCommand: (...args) => redisClient.sendCommand(args),
    }),
    windowMs: 1 * 60 * 1000, // ১ মিনিট
    max: 30, // সর্বোচ্চ ৩০টি অনুরোধ
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: keyGenerator,
    message: { success: false, error: "আপনি খুব দ্রুত অনুরোধ পাঠাচ্ছেন। অনুগ্রহ করে ১ মিনিট পর আবার চেষ্টা করুন।" },
});

const strictLimiter = rateLimit({
   store: new RedisStore({
       sendCommand: (...args) => redisClient.sendCommand(args),
   }),
    windowMs: 15 * 60 * 1000, // ১৫ মিনিট
    max: 5, // সর্বোচ্চ ৫টি অনুরোধ
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: keyGenerator,
    message: { success: false, error: "আপনি এই কাজটি করার জন্য নির্ধারিত সীমা অতিক্রম করেছেন।" },
});

const verifyTelegramAuth = (req, res, next) => {
    const authHeader = req.headers['x-telegram-auth'];
    const botToken = process.env.API_SECRET_TOKEN;
    if (!authHeader) {
        console.warn("Verification failed: No auth header");
        return res.status(401).send({ error: 'Unauthorized: No authentication data.' });
    }
    if (!botToken) {
        console.error("Verification failed: Server missing API_SECRET_TOKEN");
        return res.status(500).send({ error: 'Server configuration error.' });
    }

    const initData = new URLSearchParams(authHeader);
    const hash = initData.get('hash');
    const dataToCheck = [];
    initData.sort();
    initData.forEach((val, key) => {
        if (key !== 'hash') {
            dataToCheck.push(`${key}=${val}`);
        }
    });
    try {
        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
        const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataToCheck.join('\n')).digest('hex');
        if (calculatedHash === hash) {
            console.log("Verification successful for user:", initData.get('user'));
            next();
        } else {
            console.warn("Verification failed: Hash mismatch.");
            return res.status(403).send({ error: 'Forbidden: Invalid authentication data.' });
        }
    } catch (error) {
        console.error("Error during verification:", error);
        return res.status(500).send({ error: 'Internal server error during authentication.' });
    }
};

app.get('/', (req, res) => {
    res.status(200).send('Hello! The Earn Easy Backend Server is running correctly.');
});
app.post('/verifySession', verifyTelegramAuth, (req, res) => {
    res.status(200).send({ success: true, message: 'Session verified successfully.' });
});
app.get('/getInitialData', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const initData = new URLSearchParams(req.headers['x-telegram-auth']);
        const userObj = JSON.parse(initData.get('user'));
        const userId = String(userObj.id);
        const userRef = db.collection('users').doc(userId);
        let userDoc = await userRef.get();
        if (!userDoc.exists) {
            console.log(`New user detected: ${userId}. Checking auto-ban status...`);
            const autoBanDoc = await db.collection('settings').doc('auto_ban').get();
            if (autoBanDoc.exists && autoBanDoc.data().enabled === true && new Date() > autoBanDoc.data().ban_after_timestamp.toDate()) {
                console.log(`Auto-banning new user: ${userId}. No data will be saved.`);
                return res.status(403).send({ 
                    success: false, 
                    error: 'banned', 
                    banType: 'new_user_auto_ban'
                });
            }
            console.log(`Creating profile for new user: ${userId}`);
            const startParam = initData.get('start_param');
            const newUserData = {
                id: Number(userId),
                first_name: userObj.first_name || 'User',
                last_name: userObj.last_name || '',
                username: userObj.username || 'N/A',
                available_balance: 0,
                total_earnings: 0,
                lifetime_ads_watched: 0,
                daily_ads_completed: 0,
                last_ad_date: null,
                referral_count: 0,
                last_seen: admin.firestore.FieldValue.serverTimestamp(),
                seenNotificationTimestamp: null,
                is_banned: false,
                join_date: admin.firestore.FieldValue.serverTimestamp(),
                referred_by: (startParam && startParam !== userId) ? startParam : null
            };
            await userRef.set(newUserData);
            if (newUserData.referred_by) {
                const referrerRef = db.collection('users').doc(newUserData.referred_by);
                const settingsDoc = await db.collection('settings').doc('global_settings').get();
                const referralSettings = settingsDoc.exists ? (settingsDoc.data().referral || {}) : {};
                await referrerRef.update({ referral_count: admin.firestore.FieldValue.increment(1) });
                await referrerRef.collection('referrals').doc(userId).set({
                    referralId: userId,
                    status: 'pending',
                    unlocksAt: referralSettings.referral_unlock_threshold || 50,
                    joinedAt: admin.firestore.FieldValue.serverTimestamp()
                });
            }
            userDoc = await userRef.get();
        }
        const userData = userDoc.data();
        if (userData.is_banned === true) {
            return res.status(403).send({ 
                success: false, 
                error: 'banned',
                banType: 'existing_user_banned'
            });
        }
        const settingsDoc = await db.collection('settings').doc('global_settings').get();
        const allSettings = settingsDoc.exists ? settingsDoc.data() : {};
const safeSettings = {
            tasks: {
                daily_task_limit: allSettings.tasks?.daily_task_limit || 200,
                currency: allSettings.tasks?.currency || '',
            },
            api: {
                bot_username: allSettings.api?.bot_username || 'username_bot',
                networks: allSettings.api?.ad_networks || []
            },
            withdraw: allSettings.withdraw || { enabled: false, disabledMessage: "Withdrawal is temporarily disabled." },
        click_settings: {
             alert_message: allSettings.click_settings?.alert_message || "বিজ্ঞাপনে ক্লিক করে ৩০ সেকেন্ড অপেক্ষা করুন। আপনি কি প্রস্তুত?",
             direct_link: allSettings.click_settings?.direct_link || '',
             click_wait_time: allSettings.click_settings?.click_wait_time || '30'
        }            
        }
        const notifications = [];
        const globalNotificationDoc = await db.collection('settings').doc('notification').get();
        if (globalNotificationDoc.exists) {
            const noticeData = globalNotificationDoc.data();
            const userLastSeen = userData.seenNotificationTimestamp?.toMillis() || 0;
            const noticeSentAt = noticeData.sent_at?.toMillis() || 0;
            if (noticeData.message && noticeSentAt > userLastSeen) {
                notifications.push({ type: 'global', message: noticeData.message, timestamp: noticeData.sent_at });
            }
        }
        res.status(200).send({
            success: true,
            userData: userData,
            settings: safeSettings,
            notifications: notifications
        });
    } catch (error) {
        console.error("Error fetching initial data:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});

app.get('/getNextTask', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { userId } = req.query;
        if (!userId) {
            return res.status(400).send({ error: 'User ID is required.' });
        }
        const userRef = db.collection('users').doc(String(userId));
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).send({ error: 'User not found.' });
        }
        const userData = userDoc.data();
        const dailyCompleted = userData.daily_ads_completed || 0;
        const nextClickTarget = userData.next_click_target;
        let taskType = 'View';
        if (nextClickTarget && dailyCompleted >= nextClickTarget) {
            taskType = 'Click';
        } 
        else if (!nextClickTarget) {
            const settingsDoc = await db.collection('settings').doc('global_settings').get();
            const taskSettings = settingsDoc.exists ? (settingsDoc.data().tasks || {}) : {};
            const viewsBeforeClick = taskSettings.views_before_click || '10-20';
            const parts = viewsBeforeClick.split('-').map(Number);
            const min = parts[0] || 10;
            const max = parts[1] || 20;
            const initialInterval = Math.floor(Math.random() * (max - min + 1)) + min;
            await userRef.update({
                next_click_target: initialInterval,
                last_click_interval: initialInterval
            });
            if (dailyCompleted >= initialInterval) {
                taskType = 'Click';
            }
        }
        res.status(200).send({ success: true, taskType: taskType });
    } catch (error) {
        console.error("Error getting next task:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});

app.post('/completeTask', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { userId, taskType } = req.body;
        if (!userId || !taskType) return res.status(400).send({ error: 'User ID and Task Type are required.' });

        const userRef = db.collection('users').doc(String(userId));
                const initialUserDoc = await userRef.get();
        if (initialUserDoc.exists && initialUserDoc.data().is_banned === true) {
            return res.status(403).send({ success: false, error: 'banned' });
        }
        const settingsDoc = await db.collection('settings').doc('global_settings').get(); 
        if (!settingsDoc.exists) {
            throw new Error("Critical: Global settings not found.");
        }
        const globalSettings = settingsDoc.data();
        const taskSettings = globalSettings.tasks || {};
        const referralSettingsData = globalSettings.referral || {};
        const referralSettings = {
            referral_unlock_threshold: referralSettingsData.referral_unlock_threshold || 50,
            referral_commission_percentage: (referralSettingsData.referral_commission / 100) || 0.00
        };
        if (taskType === 'Click') {
            const userDoc = await userRef.get();
            const userData = userDoc.data();
            if (!userData || !userData.click_task_started_at) {
                return res.status(403).send({ success: false, error: 'Click task was not initiated correctly.' });
            }
            const startTime = userData.click_task_started_at.toDate();
            const waitSeconds = userData.click_task_wait_seconds || 30;
            const timeDiff = (new Date() - startTime) / 1000;
            if (timeDiff < waitSeconds) {
                await userRef.update({
                    click_task_started_at: admin.firestore.FieldValue.delete(),
                    click_task_wait_seconds: admin.firestore.FieldValue.delete()
                });
                return res.status(403).send({ success: false, error: 'You did not wait long enough.' });
            }
        }
        const reward = (taskType === 'Click') ? (taskSettings.click_task_reward || 0) : (taskSettings.view_task_reward || 0);
        const shouldIncrementClick = taskType === 'Click' && globalSettings.click_settings && globalSettings.click_settings.direct_link;
        const transactionResult = await db.runTransaction(async (t) => {
            const userDoc = await t.get(userRef);
            if (!userDoc.exists) throw new Error("User not found!");
            let userData = userDoc.data();
            const dailyTaskLimit = taskSettings.daily_task_limit || 200;

            const today = new Date(new Date().getTime() + (6 * 60 * 60 * 1000));
            const todayString = today.toISOString().split('T')[0];
            const lastAdDate = userData.last_ad_date || '';
            const isNewDay = lastAdDate !== todayString;

            const dailyCompleted = isNewDay ? 0 : (userData.daily_ads_completed || 0);

            if (dailyCompleted >= dailyTaskLimit) {
                throw new Error("Daily task limit reached.");
            }

            const { referred_by } = userData;
            let referrerRef = null;
            let referralStatusRef = null;
            let referralStatusDoc = null;
            if (referred_by) {
                referrerRef = db.collection('users').doc(referred_by);
                referralStatusRef = referrerRef.collection('referrals').doc(String(userId));
                referralStatusDoc = await t.get(referralStatusRef);
            }
            
            const newDailyAdsCompleted = dailyCompleted + 1;
            
            const userUpdateData = {
                available_balance: admin.firestore.FieldValue.increment(reward),
                total_earnings: admin.firestore.FieldValue.increment(reward),
                lifetime_ads_watched: admin.firestore.FieldValue.increment(1),
                daily_ads_completed: newDailyAdsCompleted,
                last_seen: admin.firestore.FieldValue.serverTimestamp()
            };

            if (isNewDay) {
                userUpdateData.last_ad_date = todayString;
                userUpdateData.tasks_completed_today = false;
                userUpdateData.tasks_completed_timestamp = admin.firestore.FieldValue.delete();
                userUpdateData.next_click_target = admin.firestore.FieldValue.delete();
                userUpdateData.last_click_interval = admin.firestore.FieldValue.delete();
            }

            const streakAlreadyUpdatedToday = !isNewDay && dailyCompleted >= 10;
            
            if (newDailyAdsCompleted >= 10 && !streakAlreadyUpdatedToday) {
                const yesterday = new Date(today);
                yesterday.setDate(yesterday.getDate() - 1);
                const yesterdayString = yesterday.toISOString().split('T')[0];
                const lastAdDateForStreak = userData.last_ad_date || '';

                if (lastAdDateForStreak === yesterdayString) {
                    userUpdateData.consecutive_days_streak = admin.firestore.FieldValue.increment(1);
                } else {
                    userUpdateData.consecutive_days_streak = 1;
                }
            }

            if (newDailyAdsCompleted >= dailyTaskLimit) {
                userUpdateData.tasks_completed_today = true;
                userUpdateData.tasks_completed_timestamp = admin.firestore.FieldValue.serverTimestamp();
            }
            
            if (taskType === 'Click') {
                userUpdateData.click_task_started_at = admin.firestore.FieldValue.delete();
                userUpdateData.click_task_wait_seconds = admin.firestore.FieldValue.delete();
                const viewsBeforeClick = taskSettings.views_before_click || '10-20';
                const parts = viewsBeforeClick.split('-').map(Number);
                const min = parts[0] || 10;
                const max = parts[1] || 20;
                let newInterval;
                const lastInterval = userData.last_click_interval || 0;
                do {
                    newInterval = Math.floor(Math.random() * (max - min + 1)) + min;
                } while (newInterval === lastInterval && (max - min > 0));
                userUpdateData.next_click_target = newDailyAdsCompleted + newInterval;
                userUpdateData.last_click_interval = newInterval;
            }
            t.update(userRef, userUpdateData);
            
            const newTotalEarnings = (userData.total_earnings || 0) + reward;
            if (referred_by && referralStatusDoc && referralStatusDoc.exists) {
                const referralData = referralStatusDoc.data();
                if (referralData.status === 'pending' && newTotalEarnings >= referralSettings.referral_unlock_threshold) {
                    t.update(referralStatusRef, { status: 'active' });
                } else if (referralData.status === 'active') {
                    const commission = reward * referralSettings.referral_commission_percentage;
                    if (commission > 0) {
                        t.update(referrerRef, {
                            available_balance: admin.firestore.FieldValue.increment(commission),
                            total_earnings: admin.firestore.FieldValue.increment(commission)
                        });
                    }
                }
            }
            if (shouldIncrementClick) {
                const statsRef = db.collection('statistics').doc('global');
                t.set(statsRef, { total_ad_clicks: admin.firestore.FieldValue.increment(1) }, { merge: true });
            }
            return { reward };
        });
const finalUserDoc = await userRef.get(); 
res.status(200).send({ 
    success: true, 
    reward: transactionResult.reward,
    updatedUser: finalUserDoc.data() 
});
    } catch (error) {
        console.error("Error completing task:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});

app.post('/startClickTask', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { userId, waitSeconds } = req.body;
        if (!userId || !waitSeconds) {
            return res.status(400).send({ error: 'User ID and wait time are required.' });
        }
        const userRef = db.collection('users').doc(String(userId));
        const userDoc = await userRef.get();
        if (userDoc.exists && userDoc.data().is_banned === true) {
            return res.status(403).send({ success: false, error: 'banned' });
        }
        await userRef.update({
            click_task_started_at: admin.firestore.FieldValue.serverTimestamp(),
            click_task_wait_seconds: waitSeconds
        });
        res.status(200).send({ success: true });
    } catch (error) {
        console.error("Error starting click task:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});

app.post('/requestWithdrawal', strictLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { withdrawalData, requestedAmount } = req.body;
        if (!withdrawalData || !requestedAmount || !withdrawalData.userId || !withdrawalData.method) {
            return res.status(400).send({ success: false, error: "Withdrawal data is incomplete." });
        }
        const { userId, method } = withdrawalData;
        const userRef = db.collection('users').doc(String(userId));
        const userDocCheck = await userRef.get();
        if (userDocCheck.exists && userDocCheck.data().is_banned === true) {
            return res.status(403).send({ success: false, error: 'banned' });
        }
        const pendingCheckQuery = await db.collection('withdrawals')
            .where('userId', '==', userId)
            .where('status', '==', 'pending')
            .where('method', '==', method)
            .limit(1)
            .get();
        if (!pendingCheckQuery.empty) {
            return res.status(409).send({ 
                success: false, 
                error: "আপনি এই মাধ্যমে আর পেমেন্ট নিতে পারবেন না। কারণ আপনি ইতিমধ্যে এই মাধ্যমে একবার পেমেন্ট নিয়েছেন।\n\nযদি একান্তই পেমেন্ট নিতে চান তাহলে Withdrawal Method থেকে আলাদা অপশন নির্বাচন করুন।\n\n\nসাথে থাকার জন্য ধন্যবাদ।" 
            });
        }
        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) {
                throw new Error("User not found.");
            }
            const currentBalance = userDoc.data().available_balance || 0;
            if (currentBalance < requestedAmount) {
                throw new Error("Your available balance is insufficient.");
            }
            transaction.update(userRef, {
                available_balance: admin.firestore.FieldValue.increment(-requestedAmount)
            });
            const withdrawalRef = db.collection('withdrawals').doc();
            transaction.set(withdrawalRef, {
                ...withdrawalData,
                request_date: admin.firestore.FieldValue.serverTimestamp()
            });
        });
        const finalUserDoc = await userRef.get();
        res.status(200).send({ 
            success: true, 
            message: "Withdrawal request submitted successfully.",
            updatedUser: finalUserDoc.data()
        });
    } catch (error) {
        console.error("Error submitting withdrawal request:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});

app.post('/markGlobalNotificationSeen', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) {
            return res.status(400).send({ error: 'User ID is required.' });
        }
        const seenTimestamp = admin.firestore.FieldValue.serverTimestamp();
        const userRef = db.collection('users').doc(String(userId));
        await userRef.update({ seenNotificationTimestamp: seenTimestamp });
        res.status(200).send({ success: true, message: 'Global notification marked as seen.' });
    } catch (error) {
        console.error("Error marking global notification as seen:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});

app.post('/markTargetedNotificationSeen', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { notificationId, username } = req.body;
        if (!notificationId || !username) {
            return res.status(400).send({ error: 'Notification ID and username are required.' });
        }
        const notificationRef = db.collection('notifications').doc(notificationId);
        await notificationRef.update({
            seenBy: admin.firestore.FieldValue.arrayUnion(username)
        });
        res.status(200).send({ success: true, message: 'Targeted notification marked as seen.' });
    } catch (error) {
        console.error("Error marking targeted notification as seen:", error);
        res.status(500).send({ success: false, error: error.message });
}
});

app.post('/markNotificationSeen', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { notificationId } = req.body;
        if (!notificationId) {
            return res.status(400).send({ error: 'Notification ID is required.' });
        }
        const notificationRef = db.collection('notifications').doc(notificationId);
        await notificationRef.update({
            seen: true
        });
        res.status(200).send({ success: true, message: 'Notification marked as seen.' });
    } catch (error) {
        console.error("Error marking notification as seen:", error);
        res.status(500).send({ success: false, error: error.message });
    }
});
app.get('/getActiveReferralCount', generalLimiter, verifyTelegramAuth, async (req, res) => {
    try {
        const { userId } = req.query;
        if (!userId) {
            return res.status(400).send({ success: false, error: "User ID is required." });
        }
        const referralsRef = db.collection('users').doc(String(userId)).collection('referrals');
        const snapshot = await referralsRef.get();
        if (snapshot.empty) {
            await db.collection('users').doc(String(userId)).update({ referral_count: 0 });
            return res.status(200).send({ success: true, activeReferralCount: 0 });
        }
        const userPromises = snapshot.docs.map(doc => {
            const referralId = doc.data().referralId;
            return db.collection('users').doc(String(referralId)).get();
        });
        const userDocs = await Promise.all(userPromises);
        let activeReferralCount = 0;
        userDocs.forEach(userDoc => {
            if (userDoc.exists && !userDoc.data().is_banned) {
                activeReferralCount++;
            }
        });
        const userRef = db.collection('users').doc(String(userId));
        await userRef.update({ referral_count: activeReferralCount });
        res.status(200).send({ success: true, activeReferralCount: activeReferralCount });
    } catch (error) {
        console.error("Error calculating and updating active referrals:", error);
        res.status(500).send({ success: false, error: "Internal server error." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
module.exports = app;