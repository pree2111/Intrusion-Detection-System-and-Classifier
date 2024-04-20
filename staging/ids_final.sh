echo "Hi!Welcome to our project!"
#!/bin/bash

run_bcc() {
    echo "Running BCC code..."
    python3 realtime.py &

    sleep 30
    echo "Killing BCC code..."
    pkill -f bcc_code.py
}

run_preprocessing() {
    echo "Running preprocessing script..."
    python3 preprocessing.py

    echo "Preprocessing output:"
    cat output.csv
}


while true; do
    run_bcc
    run_preprocessing
done

