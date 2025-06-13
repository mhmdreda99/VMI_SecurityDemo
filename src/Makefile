# Makefile for Stealthium VMI Demo
# Compiles the complete VMI demonstration program

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
LDFLAGS = -lvmi

# Directories
SRC_DIR = .
BUILD_DIR = build

# Source files
SOURCES = vmi_stealthium_demo.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = stealthium_vmi_demo

# Default target
all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Main target
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

# Object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -rf $(BUILD_DIR)

# Install target (optional)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

# Run the demo
run: $(TARGET)
	sudo ./$(TARGET) win7-vmi

# Debug version
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# Check VMI setup
check-vmi:
	@echo "Checking VMI setup..."
	@virsh list --all | grep win7-vmi || echo "VM win7-vmi not found"
	@sudo vmi-process-list win7-vmi | head -3 || echo "VMI not working"

# Help
help:
	@echo "Available targets:"
	@echo "  all       - Build the VMI demo (default)"
	@echo "  clean     - Remove build artifacts" 
	@echo "  run       - Build and run the demo"
	@echo "  debug     - Build debug version"
	@echo "  check-vmi - Check if VMI setup is working"
	@echo "  help      - Show this help"

.PHONY: all clean install run debug check-vmi help