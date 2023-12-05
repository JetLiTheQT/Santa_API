const express = require('express');
const { Datastore } = require('@google-cloud/datastore');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const bodyParser = require('body-parser');
const { auth, requiresAuth } = require('express-openid-connect');

const app = express();
const datastore = new Datastore();
const login = express.Router();
const USER = "User";
const RECIPIENT = "Recipient";
const GIFT = "Gift";

const CLIENT_ID = 'Kug4M6jMStUcsX3EZwI2268z60xHMrMu';
const CLIENT_SECRET = 'wnHiZKRsge6RIml39M47q9wYVP_QMKSNyJKE-8nXeIrfEzQmoK3CHx-nQz5a1gCk';
const DOMAIN = '493-final-proj.us.auth0.com';

app.use(bodyParser.json());

// Auth0 configuration
const config = {
    authRequired: false,
    auth0Logout: true,
    // baseURL: 'https://finalproj-407105.uw.r.appspot.com/', // Replace with your base URL
    baseURL: 'http://localhost:8080/',
    clientID: CLIENT_ID,
    issuerBaseURL: `https://${DOMAIN}`,
    secret: CLIENT_SECRET
};
app.use(auth(config));

// JWT check configuration
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
  }),
  issuer: `https://${DOMAIN}/`,
  algorithms: ['RS256']
});
app.get('/', (req, res) => {
    if (req.oidc && req.oidc.isAuthenticated()) {
        // User is authenticated
        const userInfo = req.oidc.user;
    
        res.send(`
            <html>
                <body>
                    <h1>Welcome to Jet's Final Project</h1>
                    <p>You are logged in as ${userInfo.name}</p>
                    <a href="/profile">View JWT Token</a> <br> </br>
                    <a href="/logout">Logout</a>
                </body>
            </html>
        `);
    } else {
        // User is not authenticated, show login link
        res.send(`
            <html>
                <body>
                    <h1>Welcome to Jet's Final Project</h1>
                    <p><a href="/login">Log in</a></p>
                </body>
            </html>
        `);
    }
    });
    
// Helper functions for Datastore
function fromDatastore(item) {
  item.id = item[Datastore.KEY].id;
  return item;
}
app.use(async (req, res, next) => {
    if (req.oidc && req.oidc.user) {
        const userID = req.oidc.user.sub;
        const key = datastore.key([USER, userID]);
        const [user] = await datastore.get(key);

        if (!user) {
            // User does not exist, so create a new user entity
            const newUser = { userID: userID };
            await datastore.save({ key: key, data: newUser });
            console.log('New user added to datastore:', userID);
        }
        next();
    } else {
        next();
    }
});
// Function to get paginated results
function getEntities(kind, limit, cursor, filterKey, filterValue) {
  let query = datastore.createQuery(kind).limit(limit);
  if (cursor) {
    query = query.start(cursor);
  }
  if (filterKey && filterValue) {
    query = query.filter(filterKey, '=', filterValue);
  }
  return datastore.runQuery(query);
}


// Create a new user
app.post('/users', async (req, res) => {
    const userKey = datastore.key(USER);
    const newUser = {
        name: req.body.name,
        password: req.body.password
    };
    try {
        await datastore.save({ key: userKey, data: newUser });
        res.status(201).send({ id: userKey.id, ...newUser });
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Retrieve all users NO PAGINATION REQUIRED, unprotected
app.get('/users', async (req, res) => {
    const limit = 5; // Number of results per page
    const cursor = req.query.cursor; // Cursor for pagination
    try {
        const [users, info] = await getEntities(USER, limit, cursor);
        const results = {
            users: users.map(fromDatastore),
            nextPage: info.moreResults !== Datastore.NO_MORE_RESULTS ? info.endCursor : null
        };
        res.status(200).send(results);
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});


// Retrieve a specific user
app.get('/users/:userId', checkJwt, async (req, res) => {
    const userId = parseInt(req.params.userId);
    const key = datastore.key([USER, userId]);
    try {
        const [user] = await datastore.get(key);
        if (!user) {
            return res.status(404).send({ error: 'User not found' });
        }
        res.status(200).send(fromDatastore(user));
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Recipient routes
app.post('/recipients', checkJwt, async (req, res) => {
    // Check if Accept header allows application/json
    if (!req.accepts('application/json')) {
        return res.status(406).send({ error: 'Not Acceptable - Only application/json is supported' });
    }
    const recipientKey = datastore.key(RECIPIENT);
    const newRecipient = {
        name: req.body.name,
        age: req.body.age,
        gifts: [], // Initially empty array of gifts
    };

    try {
        await datastore.save({ key: recipientKey, data: newRecipient });
        res.status(201).send({ id: recipientKey.id, ...newRecipient });
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// // Create a new pet
// app.post('/pets', checkJwt, async (req, res) => {
//     // Check if Accept header allows application/json
//     if (!req.accepts('application/json')) {
//         return res.status(406).send({ error: 'Not Acceptable - Only application/json is supported' });
//     }

//     const petKey = datastore.key(PET);
//     const newPet = {
//         name: req.body.name,
//         age: req.body.age,
//         breed: req.body.breed,
//         owner: req.oidc && req.oidc.user ? req.oidc.user.sub : null,
//     };

//     try {
//         await datastore.save({ key: petKey, data: newPet });
//         res.status(201).send({ id: petKey.id, ...newPet });
//     } catch (error) {
//         res.status(500).send({ error: 'Internal Server Error' });
//     }
// });


// Retrieve all pets for the logged-in user with pagination
app.get('/recipients', checkJwt, async (req, res) => {
    const limit = 5; // Number of results per page
    const cursor = req.query.cursor; // Cursor for pagination
    try {
        const [recipients, info] = await getEntities(recipients, limit, cursor, 'owner', req.user.sub);
        const results = {
            recipients: recipients.map(fromDatastore),
            nextPage: info.moreResults !== Datastore.NO_MORE_RESULTS ? info.endCursor : null
        };
        res.status(200).send(results);
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Retrieve a specific pet
app.get('/recipients/:recipientsId', checkJwt, async (req, res) => {
    const recipientsId = parseInt(req.params.recipientsId);
    const key = datastore.key([RECIPIENT, recipientsId]);
    try {
        const [recipients] = await datastore.get(key);
        if (!recipients || recipients.owner !== req.user.sub) {
            return res.status(404).send({ error: 'Recipients not found or unauthorized' });
        }
        res.status(200).send(fromDatastore(recipients));
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Update a pet
app.put('/recipients/:recipientsId', checkJwt, async (req, res) => {
    const recipientsId = parseInt(req.params.petId);
    const key = datastore.key([RECIPIENT, recipientsId]);
    try {
        const [recipients] = await datastore.get(key);
        if (!recipients || recipients.owner !== req.user.sub) {
            return res.status(404).send({ error: 'Recipients not found or unauthorized' });
        }
        const updatedRecipients = {
            name: req.body.name,
            gifts: [],
            // Add other properties to be updated
        };
        await datastore.save({ key: key, data: updatedRecipients });
        res.status(200).send({ id: recipientsId, ...updatedRecipients });
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Delete a pet
app.delete('/recipients/:recipientsId', checkJwt, async (req, res) => {
    const recipientsId = parseInt(req.params.recipientsId);
    const key = datastore.key([RECIPIENT, recipientsId]);
    try {
        const [recipients] = await datastore.get(key);
        if (!recipients || recipients.owner !== req.user.sub) {
            return res.status(404).send({ error: 'Recipients not found or unauthorized' });
        }
        await datastore.delete(key);
        res.status(204).end();
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Gift routes
app.post('/gifts', checkJwt, async (req, res) => {
    const giftKey = datastore.key(GIFT);
    const newGift = {
        description: req.body.description,
        price: req.body.price,
        giver: req.oidc.user, // User ID from JWT
        recipientId: req.body.recipientId, // Recipient ID
    };

    try {
        await datastore.save({ key: giftKey, data: newGift });
        const giftId = giftKey.id;
        const recipientKey = datastore.key([RECIPIENT, parseInt(req.body.recipientId)]);
        
        // Fetch the recipient
        const [recipient] = await datastore.get(recipientKey);
        if (!recipient) {
            return res.status(404).send({ error: 'Recipient not found' });
        }

        // Add the new gift to the recipient's gifts array
        recipient.gifts = recipient.gifts || [];
        recipient.gifts.push(giftId);

        // Update the recipient in the datastore
        await datastore.save({ key: recipientKey, data: recipient });

        res.status(201).send({ id: giftId, ...newGift });
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});



// Retrieve all gifts given by the logged-in user with pagination
app.get('/gifts', checkJwt, async (req, res) => {
    const limit = 5; // Number of results per page
    const cursor = req.query.cursor; // Cursor for pagination
    try {
        // Fetch gifts given by the logged-in user
        const [gifts, info] = await getEntities(GIFT, limit, cursor, 'giver', req.user.sub);
        const results = {
            gifts: gifts.map(fromDatastore),
            nextPage: info.moreResults !== Datastore.NO_MORE_RESULTS ? info.endCursor : null
        };
        res.status(200).send(results);
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Retrieve a specific gift
app.get('/gifts/:giftId', checkJwt, async (req, res) => {
    const giftId = parseInt(req.params.giftId);
    const key = datastore.key([GIFT, giftId]);
    try {
        const [gift] = await datastore.get(key);
        if (!gift) {
            return res.status(404).send({ error: 'Gift not found' });
        }
        if (gift.giver !== req.user.sub) {
            return res.status(403).send({ error: 'Unauthorized access to this gift' });
        }
        res.status(200).send(fromDatastore(gift));
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Update a gift
app.put('/gifts/:giftId', checkJwt, async (req, res) => {
    const giftId = parseInt(req.params.giftId);
    const key = datastore.key([GIFT, giftId]);
    try {
        const [gift] = await datastore.get(key);
        if (!gift) {
            return res.status(404).send({ error: 'Gift not found' });
        }
        if (gift.giver !== req.user.sub) {
            return res.status(403).send({ error: 'Unauthorized access to this gift' });
        }
        const updatedGift = {
            price: req.body.price,
            weight: req.body.weight,
            giver: gift.giver, // Keep the original giver
            recipientId: gift.recipientId, // Keep the original recipientId
            // Add other properties to be updated
        };
        await datastore.save({ key: key, data: updatedGift });
        res.status(200).send({ id: giftId, ...updatedGift });
    } catch (error){
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Delete a gift
app.delete('/gifts/:giftId', checkJwt, async (req, res) => {
    const giftId = parseInt(req.params.giftId);
    const key = datastore.key([GIFT, giftId]);
    try {
        const [gift] = await datastore.get(key);
        if (!gift) {
            return res.status(404).send({ error: 'Gift not found' });
        }
        if (gift.giver !== req.user.sub) {
            return res.status(403).send({ error: 'Unauthorized access to this gift' });
        }
        await datastore.delete(key);
        res.status(204).end();
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

app.get('/profile', requiresAuth(), (req, res) => {
    const userInfo = {
        userID: req.oidc.user.sub,
        jwt: req.oidc.idToken // or req.oidc.accessToken depending on your needs
    };
    res.status(200).json(userInfo);
});
login.post('/', function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    var options = { 
        method: 'POST',
        url: `https://${DOMAIN}/oauth/token`,
        headers: { 'content-type': 'application/json' },
        body:
            { grant_type: 'password',
            username: username,
            password: password,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET 
        },
        json: true 
        };
    request(options, (error, response, body) => {
        if (error){
            res.status(500).send(error);
        } else {
            res.send(body);
        }
    });
});
app.use('/login', login);
app.use((req, res, next) => {
    console.log('User object:', req.user);
    next();
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});
