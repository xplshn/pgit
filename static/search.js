document.addEventListener('DOMContentLoaded', () => {
  // Only run search logic on the search page
  if (document.querySelector('#search-results-container')) {
    const resultsContainer = document.getElementById('search-results-container');
    let searchIndex = [];

    async function executeSearch() {
      try {
        const response = await fetch('search-index.json');
        if (!response.ok) {
          resultsContainer.innerHTML = '<p>Error: Could not load search index.</p>';
          return;
        }
        searchIndex = await response.json();

        const urlParams = new URLSearchParams(window.location.search);
        const query = urlParams.get('q');

        // Update the search input in the header to reflect the current query
        const headerSearchInput = document.getElementById('search-input');
        if (headerSearchInput && query) {
            headerSearchInput.value = query;
        }

        if (!query) {
          resultsContainer.innerHTML = '<p>Please enter a search term.</p>';
          return;
        }

        const results = searchIndex.filter(item =>
          item.name.toLowerCase().includes(query.toLowerCase()) ||
          item.path.toLowerCase().includes(query.toLowerCase())
        );

        renderResults(results, query);
      } catch (error) {
        console.error('Error during search:', error);
        resultsContainer.innerHTML = '<p>An error occurred during the search.</p>';
      }
    }

    function renderResults(results, query) {
      if (results.length === 0) {
        resultsContainer.innerHTML = `<p>No results found for "<strong>${escapeHTML(query)}</strong>".</p>`;
        return;
      }

      let html = `<p>${results.length} results found for "<strong>${escapeHTML(query)}</strong>":</p><ul>`;
      results.forEach(item => {
        html += `
          <li class="search-result-item">
            <a href="${item.url}">${highlight(item.path, query)}</a>
            <span>${item.language}</span>
          </li>`;
      });
      html += '</ul>';
      resultsContainer.innerHTML = html;
    }

    function escapeHTML(str) {
        return str.replace(/[&<>"']/g, function(match) {
            return {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            }[match];
        });
    }

    function highlight(text, query) {
        const escapedQuery = escapeHTML(query);
        const regex = new RegExp(`(${escapedQuery})`, 'gi');
        return escapeHTML(text).replace(regex, '<mark>$1</mark>');
    }

    executeSearch();
  }
});
