echo "Hi! Welcome to our project!"
echo "This is a real time threat detection model which captures your network traffic live every 30 seconds and puts it through a number of processes including a LSTM Model to predict whether any of the traffic in the 30 seconds is malicious"
echo "eBPF used for packet capture and LSTM for threat detection"
#!/bin/bash


run_bcc() {
    echo "Capturing and assessing packet data....please wait 30 seconds..."
    sudo python3 real_time.py &> /dev/null &

    sleep 30
    # echo "Killing BCC code..."
    pkill -f bcc_code.py > /dev/null 2>&1
}

run_preprocessing() {
    # echo "Running preprocessing script..."
    sudo python3 preprocessing.py > /dev/null 2>&1

    # echo "Preprocessing output:"
    cat output.txt
}


for i in {1..10}; do
    run_bcc
    run_preprocessing
done

sudo killall -9 python3