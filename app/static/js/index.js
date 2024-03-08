// Function to refresh the table content using AJAX and create a permanent table
function refreshLatestBlocksTable() {
  // Send an AJAX request to fetch updated data from the server
  fetch('/get-updated-blocks')
	.then(response => response.json())
	.then(data => {
	    // Create the table element
	    const table = document.createElement('table');
	    table.className = 'mx-auto w-4/6';
	    table.id = 'new_block';

	    // Create the table header
	    const thead = document.createElement('thead');
	    thead.innerHTML = `
		<tr class="text-center">
		    <th scope="col" class="py-3.5 pl-3 pr-3 text-sm font-medium text-base-content/50 text-right">Block</th>
		    <th scope="col" class="py-3.5 px-3 text-sm font-medium text-base-content/50 hidden lg:table-cell text-right">Hash</th>
		    <th scope="col" class="py-3.5 px-3 text-sm font-medium text-base-content/50 text-right">Time</th>
		    <th scope="col" class="py-3.5 px-3 text-sm font-medium text-base-content/50">Tx</th>
		    <th scope="col" class="py-3.5 px-3 text-sm font-medium text-base-content/50 text-right">Size</th>
		</tr>
	    `;
	    table.appendChild(thead);

	    // Create the table body
	    const tbody = document.createElement('tbody');
	    tbody.id = 'table-body';
	    data.forEach(block => {
		const newRow = `
		    <tr class="py-1">
			<td class="whitespace-nowrap pl-3 pr-3 text-sm font-medium text-base-content/75 text-right"><a href="/block/${block.hash}">${block.height}</a></td>
			<td class="whitespace-nowrap pl-3 pr-3 text-sm font-medium text-base-content/75 hidden lg:table-cell text-right"><a class="hash-link" href="/block/${block.hash}">${truncateHash(block.hash)}</a></td>
			<td class="whitespace-nowrap px-3 text-sm text-base-content/75 text-right">${block.time}</td>
			<td class="whitespace-nowrap px-3 text-sm text-base-content/75 text-right">${block.transactions}</td>
			<td class="whitespace-nowrap px-3 text-sm text-base-content/75 text-right">${block.size}<span class="text-xs">KB</span></td>
		    </tr>
		`;
		tbody.insertAdjacentHTML('beforeend', newRow);
	    });
	    table.appendChild(tbody);

	    // Replace the existing table with the new one
	    const existingTable = document.getElementById('new_block');
	    if (existingTable) {
		existingTable.parentNode.replaceChild(table, existingTable);
	    } else {
		document.getElementById('table-section').appendChild(table);
	    }

	    // Call a function to update truncated hashes if needed
	    updateTruncatedHashes();
	})
	.catch(error => console.error('Error fetching data:', error));
}

// Function to refresh the Latest Transactions table content using AJAX and create a permanent table
function refreshLatestTransactionsTable() {
  // Send an AJAX request to fetch updated data from the server
  fetch('/get-latest-tx')
	.then(response => response.json())
	.then(data => {
	    // Create the table element
	    const table = document.createElement('table');
	    table.className = 'min-w-full text-center';
	    table.id = 'new_tx';

	    // Create the table header
	    const thead = document.createElement('thead');
	    thead.innerHTML = `
		      <tr>
		          <th scope="col" class="py-3.5 pl-3 text-sm font-medium text-base-content/50 pl-6 text-left">TxID</th>
		      </tr>
	    `;
	    table.appendChild(thead);

	    // Create the table body
	    const tbody = document.createElement('tbody');
	    tbody.className = '';
	    data.forEach(transaction => {
				// Round the last 10 characters of the transaction ID
        const roundedTxId = transaction.txid.substring(0, transaction.txid.length - 30) + '...';

				const newRow = `
              <tr class="py-1">
                  <td class="whitespace-nowrap pl-3 pr-3 text-sm font-medium text-base-content/75 text-left"><a href="/tx/${transaction.txid}">${roundedTxId}</a></td>
              </tr>
		    `;
		    tbody.insertAdjacentHTML('beforeend', newRow);
	    });
	    table.appendChild(tbody);

	    // Replace the existing table with the new one
	    const existingTable = document.getElementById('new_tx');
	    if (existingTable) {
		existingTable.parentNode.replaceChild(table, existingTable);
	    } else {
		document.getElementById('table-section').appendChild(table);
	    }
	})
	.catch(error => console.error('Error fetching data:', error));
}

// Function to update truncated hashes
function updateTruncatedHashes() {
  const hashLinks = document.querySelectorAll('.hash-link');
    hashLinks.forEach(link => {
	const fullHash = link.getAttribute('href').split('/').pop();
	if (fullHash.length >= 10) {
	    const truncatedHash = fullHash.substring(0, 3) + '...' + fullHash.substring(fullHash.length - 3);
	    link.textContent = truncatedHash;
	}
    });
}

// Function to truncate hash if it's too long
function truncateHash(hash) {
    if (hash.length >= 10) {
	return hash.substring(0, 3) + '...' + hash.substring(hash.length - 3);
    }
    return hash;
}

// Refresh the Latest Blocks table content when the page loads
document.addEventListener('DOMContentLoaded', refreshLatestBlocksTable);

// Refresh the table content every 60 seconds
setInterval(refreshLatestBlocksTable, 60000);

// Refresh the Latest Transactions table content when the page loads
document.addEventListener('DOMContentLoaded', refreshLatestTransactionsTable);

// Refresh the Latest Transactions table content every 60 seconds
setInterval(refreshLatestTransactionsTable, 1000);

// Call the function to update truncated hashes when the page loads
window.onload = updateTruncatedHashes;

