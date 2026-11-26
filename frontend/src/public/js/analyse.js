
const form = document.getElementById('repoForm');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultsContent = document.getElementById('resultsContent');
const error = document.getElementById('error');
const submitBtn = document.getElementById('submitBtn');

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const repoUrl = document.getElementById('repoUrl').value;

    // Reset previous state
    results.classList.add('d-none');
    error.classList.add('d-none');
    resultsContent.innerHTML = '';

    // Show loading indicator
    loading.classList.remove('d-none');
    submitBtn.disabled = true;

    try {
        const response = await fetch('/analyse', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ repoUrl }),
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Analysis failed');
        }

        displayResults(result);

    } catch (err) {
        error.textContent = err.message;
        error.classList.remove('d-none');

        console.error('Analysis error:', err);

    } finally {
        loading.classList.add('d-none');
        submitBtn.disabled = false;
    }
});


function displayResults(data) {
    resultsContent.innerHTML = '';

    const message = document.createElement('p');
    message.textContent = data.message;
    resultsContent.appendChild(message);

    if (!data.dependencies || data.dependencies.length === 0) {
        const emptyMessage = document.createElement('p');
        emptyMessage.textContent = 'No dependencies found.';
        resultsContent.appendChild(emptyMessage);
    } else {
        data.dependencies.forEach(dependency => {
            const card = document.createElement('div');
            card.classList.add('card', 'mb-3');

            const body = document.createElement('div');
            body.classList.add('card-body');

            const heading = document.createElement('h5');
            heading.classList.add('card-title');
            heading.textContent = dependency.name;

            const version = document.createElement('p');
            version.textContent = `Installed version: ${dependency.version}`;

            const ecosystem = document.createElement('p');
            ecosystem.textContent = `Ecosystem: ${dependency.ecosystem}`;

            const source = document.createElement('p');
            source.textContent = `Source: ${dependency.source_file}`;

            const link = document.createElement('a');
            link.href = `/dependencies/${dependency._id}`;
            link.textContent = 'View details';
            link.classList.add('btn', 'btn-outline-primary');

            body.append(heading, version, ecosystem, source, link);
            card.appendChild(body);
            resultsContent.appendChild(card);
        });
    }

    results.classList.remove('d-none');
}