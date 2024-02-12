#include <iostream>

using namespace std;

// Function prototypes
void secondsToHours();
void secondsToMinutes();
void minutesToHours();
void hoursToSeconds();

int main() {
    int choice;

    do {
        // Display menu
        cout << "Simple Time Calculator" << endl;
        cout << "1. Convert seconds to hours" << endl;
        cout << "2. Convert seconds to minutes" << endl;
        cout << "3. Convert minutes to hours" << endl;
        cout << "4. Convert hours to seconds" << endl;
        cout << "5. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;

        // Perform action based on user's choice
        switch (choice) {
            case 1:
                secondsToHours();
                break;
            case 2:
                secondsToMinutes();
                break;
            case 3:
                minutesToHours();
                break;
            case 4:
                hoursToSeconds();
                break;
            case 5:
                cout << "Exiting program. Goodbye!" << endl;
                break;
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    } while (choice != 5);

    return 0;
}

// Function to convert seconds to hours
void secondsToHours() {
    int seconds;
    cout << "Enter time in seconds: ";
    cin >> seconds;
    double hours = static_cast<double>(seconds) / 3600; // 1 hour = 3600 seconds
    cout << seconds << " seconds is equal to " << hours << " hours." << endl;
}

// Function to convert seconds to minutes
void secondsToMinutes() {
    int seconds;
    cout << "Enter time in seconds: ";
    cin >> seconds;
    double minutes = static_cast<double>(seconds) / 60; // 1 minute = 60 seconds
    cout << seconds << " seconds is equal to " << minutes << " minutes." << endl;
}

// Function to convert minutes to hours
void minutesToHours() {
    int minutes;
    cout << "Enter time in minutes: ";
    cin >> minutes;
    double hours = static_cast<double>(minutes) / 60; // 1 hour = 60 minutes
    cout << minutes << " minutes is equal to " << hours << " hours." << endl;
}

// Function to convert hours to seconds
void hoursToSeconds() {
    int hours;
    cout << "Enter time in hours: ";
    cin >> hours;
    int seconds = hours * 3600; // 1 hour = 3600 seconds
    cout << hours << " hours is equal to " << seconds << " seconds." << endl;
}
