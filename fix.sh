#!/bin/bash

# Script to clean up NVR project build issues

echo "🧹 Cleaning up NVR project..."

# Step 1: Remove all backup folders
echo "Removing backup folders..."
rm -rf backup_*

# Step 2: Clean the build outputs
echo "Cleaning build outputs..."
rm -rf obj/
rm -rf bin/
dotnet clean

# Step 3: Create .gitignore to prevent future issues
echo "Creating .gitignore..."
cat > .gitignore << 'EOF'
# Build outputs
bin/
obj/
*.dll
*.exe
*.pdb

# User-specific files
*.user
*.suo
*.cache
*.userprefs

# IDE
.vs/
.vscode/
.idea/

# Backup folders
backup_*/

# Logs
*.log

# NVR specific
/var/nvr/
nvr.db
config.json

# OS files
.DS_Store
Thumbs.db
EOF

echo "✅ Cleanup complete!"
echo ""
echo "Next steps:"
echo "1. Make sure you have System.Data.SQLite.Core package installed"
echo "2. Fix the partial class issue in DatabaseService"
echo "3. Run 'dotnet restore' to restore packages"
echo "4. Run 'dotnet build' to build the project"