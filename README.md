# Fernando's SMART status aggregator

SSH into multiple servers, run `smartctl` and aggregate results into a CSV.


## Usage

1. Install `smartctl` on every host:

    ```bash
    ansible all -m shell -a 'sudo apt-get -y install smartmontools'
    ```

2. Update `smartctl`'s drive database:

    ```bash
    ansible all -m shell -a 'sudo update-smart-drivedb'
    ```

3. Run SMART "long" test on every disk of every host:

    ```bash
    ansible all -m shell -a 'smartctl --scan | cut -d "#" -f 1 | xargs -I {} smartctl -a {} -t long'
    ```
4. Add all hosts to be tested to `~/.ssh/config`, e.g.:

    ```
    Host ifill
        HostName ifill
        AddressFamily inet
        User ansbl
        ProxyJump tarbell
        IdentityFile ~/.ssh/mediacloud-ansbl-20200812
   
    # <...>
    ```
5. Run `smart_aggregate.py` against all hosts:

   ```bash
   ./smart_aggregate.py --host \
       tarbell \
       berstein \
       posey \
       bly \
       lowery \
       steinam \
       woodward \
       ramos \
       brown \
       wells \
       sinclair \
       bradley \
       ifill \
       stewart \
       guerin \
   > smart.csv
   ```
