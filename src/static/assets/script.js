document.querySelectorAll('[id="copy-key"]').forEach(element => {
    element.addEventListener('click', function(event) {
        event.preventDefault();
        const key = this.getAttribute('data-key');
        navigator.clipboard.writeText(key).then(() => {
            alert('Data copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy data: ', err);
        });
    });
});