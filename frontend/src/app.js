const axios = require('axios');
const express = require('express');
const path = require('node:path');

const app = express();

app.set('view engine', 'pug');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('views', path.join(__dirname, 'views'));


app.get('/', (req, res) => {
    res.render('index');
});

app.post('/analyse', async (req, res) => {
    try {
        const { repoUrl } = req.body;

        const response = await fetch('http://backend:8000/analyse', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ repoUrl }),
        });

        const data = await response.json();

        return res.status(response.status).json(data);

    } catch (error) {
        console.error('Error communicating with FastAPI:', error);

        return res.status(500).json({
            error: 'Could not communicate with backend',
        });
    }
});
 
app.set('view engine', 'pug');
app.use(express.static(path.join(__dirname, 'public')));
module.exports = app;