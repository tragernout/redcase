document.getElementById('upload-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const formData = new FormData(this);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(async response => {
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error('Ответ не JSON:\n' + text);
        }
        return response.json();
    })
    .then(data => {
        const statusDiv = document.getElementById('upload-status');
        if (data.success) {
            statusDiv.innerHTML = `<p style="color: green;">${data.message}</p>`;
            document.getElementById('upload-form').reset();
        } else {
            statusDiv.innerHTML = `<p style="color: red;">${data.message}</p>`;
        }
    })
    .catch(err => {
        document.getElementById('upload-status').innerHTML =
            `<p style="color: red;">Ошибка загрузки: ${err.message}</p>`;
    });
});
