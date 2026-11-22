
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

    data.dependencies.forEach(file => {
        const section = document.createElement('div');
        section.classList.add('card', 'mb-3');

        const body = document.createElement('div');
        body.classList.add('card-body');

        const heading = document.createElement('h5');
        heading.classList.add('card-title');
        heading.textContent = file.file_name;

        body.appendChild(heading);

        if (file.dependencies) {
            const list = document.createElement('ul');
            list.classList.add('list-group', 'list-group-flush');

            file.dependencies.forEach(dependency => {
                const item = document.createElement('li');
                item.classList.add('list-group-item');

                item.textContent =
                    `${dependency.name} - ${dependency.version}`;

                list.appendChild(item);
            });

            body.appendChild(list);
        } else {
            const status = document.createElement('p');
            status.textContent = file.status;
            body.appendChild(status);
        }

        section.appendChild(body);
        resultsContent.appendChild(section);
    });

    results.classList.remove('d-none');
}
