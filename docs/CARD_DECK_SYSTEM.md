# TableForge Card Deck System Documentation

*A comprehensive guide to how the card and deck system works in TableForge VTT*

## 🎴 **Overview**

TableForge implements a sophisticated card and deck management system designed for virtual tabletop gaming. The system supports multiple deck types, pile management, shuffling, dealing, and complex card operations with proper ownership and visibility controls.

---

## 🏗️ **System Architecture**

### **Core Concepts**

1. **Game Assets**: Individual card images uploaded as assets with `assetType: 'card'`
2. **Card Decks**: Collections of game assets organized into playable decks
3. **Card Piles**: Different containers for cards with specific purposes and visibility rules
4. **Deck Order**: The sequence of cards in a deck (important for shuffling and dealing)

### **Data Models**

#### **CardDeck Schema**
```typescript
interface CardDeck {
  id: string;
  name: string;
  description?: string;
  roomId: string;
  systemId?: string;
  cardBackId?: string;        // Optional custom card back
  deckOrder: string[];        // Array of asset IDs in order
  isShuffled: boolean;
  createdBy: string;
  createdAt: Date;
}
```

#### **CardPile Schema**
```typescript
interface CardPile {
  id: string;
  name: string;
  roomId: string;
  pileType: 'deck' | 'hand' | 'discard' | 'custom';
  ownerId?: string;           // For private piles
  cardOrder: string[];        // Array of asset IDs in this pile
  positionX: number;          // Board position
  positionY: number;
  visibility: 'public' | 'owner' | 'gm';
  faceDown: boolean;
  maxCards?: number;
  version: number;            // For optimistic concurrency
  createdAt: Date;
}
```

---

## 🎯 **How the Deck System Works**

### **1. Deck Creation Process**

#### **Step 1: Asset Upload**
```typescript
// GM uploads card images as game assets
const cardAsset = {
  name: "Ace of Spades",
  assetType: "card",
  filePath: "/path/to/ace-spades.jpg",
  roomId: "room-123"
};
```

#### **Step 2: Deck Assembly**
```typescript
// GM creates deck from selected card assets
const newDeck = {
  name: "Standard Playing Cards",
  description: "52-card poker deck",
  deckOrder: [asset1.id, asset2.id, asset3.id, ...], // Order matters!
  roomId: "room-123"
};
```

#### **Step 3: Main Pile Creation**
```typescript
// System automatically creates a "Main" pile for the deck
const mainPile = {
  name: `${deckName} - Main`,
  pileType: "deck",
  cardOrder: [...deckOrder],  // Copy from deck
  visibility: "public"
};
```

### **2. Deck Operations**

#### **Shuffling (Server-Authoritative)**
```typescript
// Client requests shuffle
POST /api/rooms/{roomId}/decks/{deckId}/shuffle

// Server performs Fisher-Yates shuffle
function shuffleDeck(cardOrder: string[]): string[] {
  const shuffled = [...cardOrder];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// Updates both deck.deckOrder and mainPile.cardOrder
// Broadcasts update to all players via WebSocket
```

#### **Drawing Cards**
```typescript
// Player draws card to their hand
POST /api/rooms/{roomId}/decks/{deckId}/draw
{
  count: 1,
  targetPile: "hand"  // Creates player hand if doesn't exist
}

// Server logic:
1. Remove top card(s) from main pile
2. Add to target pile (player hand, board, etc.)
3. Update pile versions for concurrency
4. Broadcast state change
```

#### **Dealing Cards**
```typescript
// GM deals cards to players or board
POST /api/rooms/{roomId}/decks/{deckId}/deal
{
  count: 5,
  targetPile: "board",     // or specific player hand
  faceDown: true
}

// Creates BoardAsset for cards dealt to board
// Cards on board can be moved, flipped, rotated
```

### **3. Pile Management**

#### **Pile Types & Purposes**
- **`deck`**: Main card storage, face-down, ordered
- **`hand`**: Player's private cards, usually hidden from others
- **`discard`**: Face-up discard pile, typically public
- **`custom`**: Special purpose piles with custom rules

#### **Visibility Controls**
- **`public`**: Visible to all players (face-up cards)
- **`owner`**: Visible only to the pile owner (player hands)
- **`gm`**: Visible only to Game Master (GM secret information)

#### **Pile Creation**
```typescript
// GM can create custom piles
const customPile = {
  name: "Treasure Cards",
  pileType: "custom",
  visibility: "public",
  positionX: 300,
  positionY: 200,
  faceDown: false
};
```

---

## 🎮 **User Interface Components**

### **CardDeckManager Component**
Located in `client/src/components/CardDeckManager.tsx`

**Features:**
- Deck creation from uploaded assets
- Preset deck templates (Playing Cards, Tarot, etc.)
- Card selection interface with filtering
- Pile management and creation
- Real-time deck state display

**Permissions:**
- **Players**: Can draw cards, view public decks
- **GM/Admin**: Full deck management, dealing, shuffling

### **ThemedDeckCard Component**
Displays individual decks with:
- Card count and deck status
- Action buttons (draw, shuffle, deal)
- Custom deck theming
- Visual representation

### **Game Board Integration**
Cards appear on the board as:
- **Deck Spots**: Visual representation of card piles
- **Individual Cards**: Moveable, rotatable card assets
- **Pile Viewers**: Click to see pile contents

---

## 🔄 **Gameplay Workflow Examples**

### **Example 1: Standard Playing Cards**

1. **Setup Phase:**
   ```typescript
   // GM uploads 52 card images
   // Creates "Standard Playing Cards" deck
   // Selects all card assets in correct order
   ```

2. **Game Start:**
   ```typescript
   // GM shuffles deck
   // Main pile shows 52 cards, face-down
   // GM deals 5 cards to each player
   ```

3. **Player Turn:**
   ```typescript
   // Player draws 1 card from deck
   // Card goes to their private hand
   // Other players see hand count increase
   ```

4. **Card Play:**
   ```typescript
   // Player drags card from hand to board
   // Card becomes public BoardAsset
   // Other players see the played card
   ```

### **Example 2: Custom Game Deck**

1. **Asset Preparation:**
   ```typescript
   // GM uploads custom game cards
   // Tags assets: "spell", "weapon", "armor"
   // Creates multiple themed decks
   ```

2. **Multiple Pile Setup:**
   ```typescript
   // "Spell Deck" - public, face-down
   // "Discard Pile" - public, face-up
   // "Player Hand" - owner only, face-up
   // "GM Secrets" - GM only, face-down
   ```

3. **Complex Operations:**
   ```typescript
   // GM shuffles spell deck
   // Player draws spell to hand
   // Player plays spell to board
   // GM moves used spell to discard pile
   ```

---

## 🔧 **Technical Implementation Details**

### **Database Relationships**
```sql
-- Core tables
cardDecks (id, name, roomId, deckOrder, ...)
cardPiles (id, name, roomId, pileType, cardOrder, ...)
gameAssets (id, name, assetType, filePath, ...)
boardAssets (id, assetId, roomId, positionX, positionY, ...)

-- Foreign key relationships
cardDecks.roomId -> gameRooms.id
cardPiles.roomId -> gameRooms.id
cardPiles.ownerId -> users.id (nullable)
boardAssets.assetId -> gameAssets.id
```

### **API Endpoints**
```typescript
// Deck operations
GET    /api/rooms/:roomId/decks
POST   /api/rooms/:roomId/decks
POST   /api/rooms/:roomId/decks/:deckId/shuffle
POST   /api/rooms/:roomId/decks/:deckId/draw
POST   /api/rooms/:roomId/decks/:deckId/deal

// Pile operations  
GET    /api/rooms/:roomId/piles
POST   /api/rooms/:roomId/piles
PATCH  /api/rooms/:roomId/piles/:pileId
DELETE /api/rooms/:roomId/piles/:pileId

// Card movement
POST   /api/rooms/:roomId/cards/move
POST   /api/rooms/:roomId/cards/transfer
```

### **WebSocket Messages**
```typescript
// Real-time updates
{
  type: 'deck_shuffled',
  roomId: 'room-123',
  payload: { deckId, newOrder }
}

{
  type: 'card_drawn',
  roomId: 'room-123', 
  payload: { playerId, cardId, sourcePile, targetPile }
}

{
  type: 'pile_updated',
  roomId: 'room-123',
  payload: { pileId, cardCount, lastAction }
}
```

---

## 🎯 **Best Practices**

### **For Game Masters**
1. **Upload assets first** before creating decks
2. **Use descriptive names** for decks and piles
3. **Set appropriate visibility** for different card types
4. **Shuffle decks** before dealing for fair play
5. **Create discard piles** for used cards

### **For Players**
1. **Understand pile types** - know where your cards are
2. **Respect visibility rules** - don't try to see hidden cards
3. **Use hands properly** - keep private cards in hand piles
4. **Communicate intent** - announce major card actions

### **For Developers**
1. **Always validate permissions** on server-side operations
2. **Use optimistic concurrency** for pile updates
3. **Broadcast state changes** via WebSocket
4. **Handle edge cases** (empty decks, full hands)
5. **Maintain card order integrity** throughout operations

---

## 🚨 **Common Issues & Solutions**

### **Issue: Cards Disappearing**
- **Cause**: Pile synchronization errors
- **Solution**: Check `cardOrder` arrays and pile versions

### **Issue: Shuffle Not Working**
- **Cause**: Client-side randomization vs server authority
- **Solution**: Always shuffle on server, broadcast results

### **Issue: Visibility Problems**
- **Cause**: Incorrect pile `visibility` or `ownerId` settings
- **Solution**: Validate user permissions before showing cards

### **Issue: Deck Order Corruption**
- **Cause**: Concurrent modifications to `cardOrder`
- **Solution**: Use version numbers and optimistic locking

---

## 🔮 **Future Enhancements**

1. **Deck Templates**: Pre-built decks for popular games
2. **Card Scripting**: Automated card effects and rules
3. **Pile Animations**: Visual feedback for card movements
4. **Deck Statistics**: Draw probability and analytics
5. **Custom Card Backs**: Per-deck visual themes
6. **Multi-Deck Games**: Support for multiple simultaneous decks

---

*Last updated: August 17, 2025*  
*Version: 1.0*  
*Status: Production Ready*
