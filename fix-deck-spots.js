// Script to fix deck spots by calling the API endpoint from within the app
console.log('Starting deck spots fix...');

fetch('/api/rooms/4b015073-552d-4c9e-958d-b5c0c887ba23/fix-deck-spots', {
  method: 'PATCH',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${localStorage.getItem('firebase-token') || 'dummy'}`
  }
})
.then(response => response.json())
.then(data => {
  console.log('Deck spots fix result:', data);
})
.catch(error => {
  console.error('Error fixing deck spots:', error);
});