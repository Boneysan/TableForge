# TableForge VTT - Comprehensive Testing Plan for Replit

*A detailed test plan for validating TableForge functionality from both Player and Game Master perspectives*

## 🎯 **Testing Overview**

This plan provides step-by-step instructions for Replit to comprehensively test TableForge's virtual tabletop functionality. The tests cover both **Game Master (GM)** and **Player** user flows to ensure the application works correctly for all user types.

### **Test Environment Setup**
- **Platform**: Replit with Node.js 20
- **Database**: PostgreSQL (built-in or external)
- **Testing Scope**: Core VTT functionality, user roles, real-time features
- **Time Estimate**: 45-60 minutes for complete testing

---

## 🚀 **Phase 1: Initial Setup & Authentication (5 minutes)**

### **Step 1.1: Launch Application**
```bash
# In Replit terminal
npm install
npm run dev
```
**Expected Result**: Application starts on port 5000, no errors in console

### **Step 1.2: Create Test Accounts**
1. **Open application URL** (Replit will provide the preview URL)
2. **Create GM Account**:
   - Click "Sign Up" 
   - Email: `gm@test.com`
   - Password: `TestPassword123!`
   - First Name: `Game`
   - Last Name: `Master`
3. **Create Player Account** (open in incognito/new browser):
   - Email: `player@test.com`
   - Password: `TestPassword123!`
   - First Name: `Test`
   - Last Name: `Player`

**Expected Result**: Both accounts created successfully, users can sign in/out

---

## 🎮 **Phase 2: Game Master Workflow Testing (20 minutes)**

### **Step 2.1: GM Room Creation**
**As Game Master (`gm@test.com`):**

1. **Create New Room**:
   - Navigate to Home page
   - Enter Room Name: `"Test Adventure Room"`
   - Click "Create Room"
   - **Expected**: Redirected to room as admin, GM Console visible

2. **Verify GM Interface**:
   - **Check**: Purple "Game Master Console" header visible
   - **Check**: GM Panel on right side with tabs: Game, Hand, Assets, Cards, Players, Chat
   - **Check**: "Switch to Admin Interface" button available
   - **Check**: Player count shows "(0 players connected)"

### **Step 2.2: Asset Management Testing**
1. **Upload Game Assets**:
   - Click "Assets" tab in GM Panel
   - Click "Upload Game Assets"
   - Upload test images (cards, tokens, maps)
   - **Expected**: Assets appear in Asset Library

2. **Place Assets on Board**:
   - Drag asset from library to game board
   - **Expected**: Asset appears on board, can be moved/rotated
   - **Check**: Asset position updates in real-time

3. **Asset Controls**:
   - Right-click asset to flip
   - Use rotation controls
   - **Expected**: All transformations work smoothly

### **Step 2.3: Card Deck Management**
1. **Create Card Deck**:
   - Click "Cards" tab
   - Click "Create Deck"
   - Add uploaded card assets to deck
   - Name deck: `"Test Playing Cards"`
   - **Expected**: Deck created with specified cards

2. **GM Hand Management**:
   - Click "Hand" tab
   - Click "Create GM Hand" (if not exists)
   - Draw cards from deck to GM hand
   - **Expected**: Cards appear in GM hand, hidden from players

3. **Card Operations**:
   - Deal cards to players (when connected)
   - Shuffle deck
   - Return cards to deck
   - **Expected**: All operations work without errors

### **Step 2.4: Game Controls**
1. **Dice Rolling**:
   - Click "Game" tab
   - Test dice rolls (d6, d20, etc.)
   - **Expected**: Dice results displayed, logged in chat

2. **Room Settings**:
   - Toggle "Private Dice Rolls"
   - Toggle "Lock Assets"
   - **Expected**: Settings persist and affect gameplay

### **Step 2.5: Player Management**
1. **Prepare for Player**:
   - Note the room URL/ID
   - Set up chat system
   - **Expected**: Ready to receive player connections

---

## 👤 **Phase 3: Player Workflow Testing (15 minutes)**

### **Step 3.1: Player Room Joining**
**As Test Player (`player@test.com`) - Use incognito/different browser:**

1. **Join Room**:
   - Navigate to Home page
   - Enter room name: `"Test Adventure Room"`
   - Click "Join Room"
   - **Expected**: Successfully joined as player, player interface shown

2. **Verify Player Interface**:
   - **Check**: Simple player interface (no GM controls)
   - **Check**: Can see game board with GM-placed assets
   - **Check**: Player name displayed correctly
   - **Check**: Dice rolling available

### **Step 3.2: Player Interactions**
1. **View Board Assets**:
   - **Check**: Can see all assets placed by GM
   - **Check**: Cannot modify/move assets (read-only)
   - **Expected**: Board updates in real-time with GM changes

2. **Dice Rolling**:
   - Roll various dice types
   - **Expected**: Results appear in chat, visible to GM

3. **Chat Communication**:
   - Send chat messages
   - **Expected**: Messages appear in both player and GM interfaces

---

## 🔄 **Phase 4: Real-Time Collaboration Testing (10 minutes)**

### **Step 4.1: Multi-User Interactions**
**Test with both GM and Player accounts open simultaneously:**

1. **Real-Time Asset Updates**:
   - **GM**: Move asset on board
   - **Player**: Verify asset moves in real-time
   - **Expected**: Instant synchronization

2. **Chat Communication**:
   - **GM**: Send message from GM chat
   - **Player**: Send message from player interface
   - **Expected**: Messages appear instantly in both interfaces

3. **Dice Roll Sharing**:
   - **Player**: Roll dice
   - **GM**: Verify dice results appear in GM interface
   - **Expected**: All dice rolls logged and shared

### **Step 4.2: Connection Stability**
1. **Refresh Testing**:
   - **Player**: Refresh browser page
   - **Expected**: Reconnects automatically, state preserved
   
2. **Network Resilience**:
   - Briefly disconnect/reconnect internet
   - **Expected**: Application recovers gracefully

---

## 🎯 **Phase 5: Advanced Features Testing (10 minutes)**

### **Step 5.1: Game Templates & Systems**
**As Game Master:**

1. **Template Management**:
   - Click "Templates" button
   - Save current room as template
   - **Expected**: Template created successfully

2. **Game Systems**:
   - Click "Game Systems" button
   - Browse/create game systems
   - **Expected**: System management interface works

### **Step 5.2: Score Management**
1. **Player Scoring**:
   - Access player scoreboard
   - Update player scores
   - **Expected**: Scores update in real-time

2. **Game State Management**:
   - Test saving/loading game state
   - **Expected**: Game state persists correctly

---

## ✅ **Success Criteria Checklist**

### **🔐 Authentication & User Management**
- [ ] User registration works
- [ ] User login/logout functions
- [ ] User roles (GM/Player) assigned correctly
- [ ] Profile editing (name changes) works

### **🏠 Room Management**
- [ ] Room creation by GM successful
- [ ] Room joining by players works
- [ ] Room URL sharing functions
- [ ] Multiple players can join same room

### **🎮 Game Master Features**
- [ ] GM Console interface loads correctly
- [ ] Asset upload and management works
- [ ] Card deck creation and management
- [ ] GM hand functionality (private cards)
- [ ] Dice rolling with results logging
- [ ] Player score management
- [ ] Real-time asset placement/movement

### **👥 Player Features**
- [ ] Player interface clean and functional
- [ ] Read-only board viewing works
- [ ] Player dice rolling functions
- [ ] Chat communication works
- [ ] Real-time updates received

### **🔄 Real-Time Functionality**
- [ ] WebSocket connections stable
- [ ] Asset movements sync instantly
- [ ] Chat messages appear immediately
- [ ] Dice rolls broadcast to all users
- [ ] Player connections/disconnections handled

### **📱 User Experience**
- [ ] Interface responsive and intuitive
- [ ] No JavaScript errors in console
- [ ] Smooth animations and transitions
- [ ] Clear visual feedback for actions
- [ ] Error messages helpful and clear

---

## 🚨 **Common Issues & Troubleshooting**

### **Database Connection Issues**
```bash
# If PostgreSQL connection fails
# Check DATABASE_URL in Replit Secrets
# Verify database is running
```

### **WebSocket Connection Problems**
```bash
# Check browser developer console for errors
# Verify port 5000 is accessible
# Check firewall/network settings
```

### **Asset Upload Failures**
```bash
# Verify file size limits (10MB max)
# Check supported file types (PNG, JPG, GIF)
# Ensure proper file permissions
```

### **Real-Time Sync Issues**
```bash
# Refresh both browser windows
# Check WebSocket connection status
# Verify both users in same room
```

---

## 📊 **Expected Performance Metrics**

### **Load Times**
- **Initial App Load**: < 3 seconds
- **Room Creation**: < 2 seconds
- **Asset Upload**: < 5 seconds (depends on file size)
- **Room Joining**: < 1 second

### **Real-Time Response**
- **Asset Movement**: < 100ms
- **Chat Messages**: < 200ms
- **Dice Roll Results**: < 300ms
- **Player Connections**: < 500ms

### **Stability**
- **No memory leaks** during 30+ minute sessions
- **WebSocket reconnection** after brief disconnects
- **State preservation** across browser refreshes

---

## 🎉 **Testing Complete - Expected Outcomes**

After completing this testing plan, you should have validated:

1. **✅ Core VTT Functionality**: Asset management, dice rolling, real-time collaboration
2. **✅ User Role System**: Proper GM/Player permissions and interfaces
3. **✅ Real-Time Features**: WebSocket communication, instant updates
4. **✅ User Experience**: Intuitive interfaces for both user types
5. **✅ Stability**: Application handles multiple users and extended sessions

### **Success Indicators**
- **GM can create and manage game sessions** with full control
- **Players can join and participate** with appropriate limitations
- **Real-time collaboration works seamlessly** between all participants
- **No critical errors or broken functionality**
- **Application performs well** under normal usage patterns

---

*Testing Plan Version: 1.0*  
*Last Updated: August 17, 2025*  
*Estimated Testing Time: 45-60 minutes*  
*Replit Compatibility: Fully optimized for Replit infrastructure*
