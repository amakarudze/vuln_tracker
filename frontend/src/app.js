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


app.get('/dependencies/:id', async (req, res) => {
    try {
        const apiUrl = 'http://backend:8000';
        const response = await fetch(
            `${apiUrl}/dependencies/${req.params.id}`
        );

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).send(data.detail);
        }

        const { dependency, metadata } = data;

        let contributors = [];
        let contributorError = null;

        const repositoryUrl = metadata?.project_urls?.Homepage;

        const githubMatch = repositoryUrl?.match(
            /github\.com\/([^/]+)\/([^/#?]+)/
        );

        if (githubMatch) {
            const [, owner, repository] = githubMatch;

            try {
                const contributorResponse = await fetch(
                    `${apiUrl}/repositories/${owner}/${repository}/contributors`
                );

                if (contributorResponse.ok) {
                    const contributorData = await contributorResponse.json();
                    contributors = contributorData.contributors || [];
                } else {
                    contributorError = 'Contributor information is unavailable.';
                }
            } catch (error) {
                console.error('Error fetching contributors:', error);
                contributorError = 'Could not retrieve contributor information.';
            }
        }

        const releases = Object.entries(metadata?.releases || {})
            .sort(([, a], [, b]) =>
                new Date(b.release_date || 0) -
                new Date(a.release_date || 0)
            );

        let vulnerabilityData = null;
        let vulnerabilityError = null;

        try {
            const vulnerabilityResponse = await fetch(
                `${apiUrl}/dependencies/${req.params.id}/vulnerabilities`
            );

            if (vulnerabilityResponse.ok) {
                vulnerabilityData = await vulnerabilityResponse.json();
            } else if (vulnerabilityResponse.status !== 404) {
                throw new Error(
                    `Vulnerability API returned ${vulnerabilityResponse.status}`
                );
            }
        } catch (error) {
            console.error("Error fetching vulnerabilities:", error);
            vulnerabilityError = "Unable to retrieve vulnerability information.";
        }

        res.render('dependency-details', {
            dependency,
            metadata,
            repositoryUrl,
            contributors,
            contributorError,
            releases,
            vulnerabilityData,
            vulnerabilityError,
        });

    } catch (err) {
        console.error('Error fetching dependency:', err);
        res.status(500).send('Could not retrieve dependency details.');
    }
});

 
app.set('view engine', 'pug');
app.use(express.static(path.join(__dirname, 'public')));
module.exports = app;