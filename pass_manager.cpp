#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <stdexcept>
#include <iomanip>
#include <map>

class PasswordManager {
private:
    std::string masterPassword;
    std::map<std::string, std::string> credentials; // Map to store username-password pairs
    std::string filename;

    // Helper functions
    bool isFileExists(const std::string& filename);
    std::string generateRandomPassword(int length);
    void encryptAndSaveToFile();
    void loadAndDecryptFromFile();

public:
    PasswordManager(const std::string& filename);
    void setMasterPassword(const std::string& password);
    bool authenticateMasterPassword(const std::string& password);
    void addCredentials(const std::string& username);
    void getCredentials(const std::string& username);
    void deleteCredentials(const std::string& username);
    void saveToFile();
    void loadFromFile();
};

PasswordManager::PasswordManager(const std::string& filename) : filename(filename) {
    if (!isFileExists(filename)) {
        std::ofstream file(filename);
        file.close();
    }
}

bool PasswordManager::isFileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

void PasswordManager::setMasterPassword(const std::string& password) {
    masterPassword = password;
}

bool PasswordManager::authenticateMasterPassword(const std::string& password) {
    return masterPassword == password;
}

std::string PasswordManager::generateRandomPassword(int length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[]|;:,.<>?";
    std::string password;
    srand(time(0)); // Seed for random number generation
    for (int i = 0; i < length; ++i) {
        password += charset[rand() % charset.length()];
    }
    return password;
}

void PasswordManager::encryptAndSaveToFile() {
    std::ofstream outFile(filename);
    if (!outFile.is_open()) {
        std::cerr << "Error: Unable to open file for writing." << std::endl;
        return;
    }

    // Write the credentials to the file
    for (const auto& entry : credentials) {
        std::string encryptedPassword = entry.second; // Encrypt the password

        // Encrypt the password using XOR cipher
        for (char& c : encryptedPassword) {
            c = c ^ 0x7F; // XOR with a fixed byte value
        }

        // Write the username and encrypted password to the file
        outFile << entry.first << " " << encryptedPassword << std::endl;
    }

    outFile.close();
}

void PasswordManager::loadAndDecryptFromFile() {
    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        std::cerr << "Error: Unable to open file for reading." << std::endl;
        return;
    }

    // Clear existing credentials
    credentials.clear();

    // Read and load the credentials from the file
    std::string username, encryptedPassword;
    while (inFile >> username >> encryptedPassword) {
        std::string decryptedPassword = encryptedPassword; // Decrypt the password

        // Decrypt the password using XOR cipher
        for (char& c : decryptedPassword) {
            c = c ^ 0x7F; // XOR with the same fixed byte value used for encryption
        }

        // Store the decrypted credentials
        credentials[username] = decryptedPassword;
    }

    inFile.close();
}

void PasswordManager::addCredentials(const std::string& username) {
    // Generate random password
    std::string password = generateRandomPassword(12);

    // Store username and password in credentials map
    credentials[username] = password;

    // Save credentials to file
    encryptAndSaveToFile();
}

void PasswordManager::getCredentials(const std::string& username) {
    // Check if username exists
    if (credentials.find(username) != credentials.end()) {
        // Display the password for the given username
        std::cout << "Password for " << username << " is: " << credentials[username] << std::endl;
    } else {
        std::cerr << "Username not found." << std::endl;
    }
}

void PasswordManager::deleteCredentials(const std::string& username) {
    // Check if username exists
    if (credentials.find(username) != credentials.end()) {
        // Delete the username-password pair
        credentials.erase(username);

        // Save changes to file
      encryptAndSaveToFile();
        std::cout << "Credentials for " << username << " deleted." << std::endl;
    } else {
        std::cerr << "Username not found." << std::endl;
    }
}

void PasswordManager::saveToFile() {
    // Save credentials to file
  std::ofstream outFile("passwords_decrypted.txt");
    if (!outFile.is_open()) {
        std::cerr << "Error: Unable to open file for writing." << std::endl;
        return;
    }

    // Write the credentials to the file
    for (const auto& entry : credentials) {
        outFile << "Username: " << entry.first << "\tPassword: " << entry.second << std::endl;
    }

    outFile.close();

}

void PasswordManager::loadFromFile() {
    std::ifstream inFile("passwords_decrypted.txt");
    if (!inFile.is_open()) {
        std::cerr << "Error: Unable to open file for reading." << std::endl;
        return;
    }

    std::string line;
    while (std::getline(inFile, line)) {
        std::cout << line << std::endl;
    }

    inFile.close();
}


int main() {
    std::string filename = "passwords.txt";
    PasswordManager manager(filename);
    std::string masterPassword;
    std::string username;

    std::cout << "Welcome to Password Manager!" << std::endl;

    // Set Master Password
    std::cout << "Please set your master password: ";
    std::cin >> masterPassword;
    manager.setMasterPassword(masterPassword);

    // Authentication
    std::string enteredPassword;
    std::cout << "Enter your master password to continue: ";
    std::cin >> enteredPassword;

    if (!manager.authenticateMasterPassword(enteredPassword)) {
        std::cerr << "Authentication failed. Exiting..." << std::endl;
        return 1;
    }
     int choice;
    while (true) {
        std::cout << "\nMenu:\n"
                  << "1. Add Credentials\n"
                  << "2. Get Credentials\n"
                  << "3. Delete Credentials\n"
                  << "4. Save to File\n"
                  << "5. Load from File\n"
                  << "6. Exit\n"
                  << "Enter your choice: ";

        // Check if the input is an integer
        if (!(std::cin >> choice)) {
            std::cerr << "Invalid input. Please enter an integer." << std::endl;
            std::cin.clear(); // Clear error flags
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            continue;
        }

        // Check if the input is within the valid range
        if (choice < 1 || choice > 6) {
            std::cerr << "Invalid choice. Please enter a number between 1 and 6." << std::endl;
            continue;
        }

        switch (choice) {
            case 1:
                std::cout << "Enter username: ";
                std::cin >> username;
                manager.addCredentials(username);
                break;
            case 2:
                std::cout << "Enter username: ";
                std::cin >> username;
                manager.getCredentials(username);
                break;
            case 3:
                std::cout << "Enter username: ";
                std::cin >> username;
                manager.deleteCredentials(username);
                break;
            case 4:
                manager.saveToFile();
                std::cout << "Data saved to file." << std::endl;
                break;
            case 5:
                manager.loadFromFile();
                std::cout << "Data loaded from file." << std::endl;
                break;
            case 6:
                std::cout << "Exiting..." << std::endl;
                return 0;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    return 0;
}