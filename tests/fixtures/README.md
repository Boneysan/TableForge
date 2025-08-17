# Test Fixtures

This directory contains test fixtures used by the E2E and integration tests.

## Files

- `test-card.png` - Sample card asset for testing asset upload and manipulation
- `test-token.png` - Sample token/piece for testing multiplayer interactions  
- `test-map.png` - Sample map background for testing board features
- `card-back.png` - Sample card back for game system testing
- `card-front.png` - Sample card front for game system testing

## Usage

These fixtures are referenced in E2E tests for file upload scenarios and visual testing. The files are small placeholder images that simulate real game assets without requiring large binary files in the repository.

## Creating Fixtures

To create test fixture images programmatically, you can use a simple 1x1 pixel PNG:

```bash
# Create a 64x96 test card
convert -size 64x96 xc:blue test-card.png

# Create a 32x32 test token  
convert -size 32x32 xc:red test-token.png

# Create a 800x600 test map
convert -size 800x600 xc:green test-map.png
```

Or use any small placeholder images for testing purposes.
