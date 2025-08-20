
set -e

make

INSTALL_DIR="/usr/bin"

echo "Installing fort++ and openfort to $INSTALL_DIR ..."
sudo cp -f fort++ "$INSTALL_DIR/"
sudo cp -f openfort "$INSTALL_DIR/"

if command -v fort++ >/dev/null 2>&1; then
    echo " fort++ installed successfully!"
else
    echo " fort++ installation failed!"
fi

if command -v openfort >/dev/null 2>&1; then
    echo "openfort installed successfully!"
else
    echo "openfort installation failed!"
fi

