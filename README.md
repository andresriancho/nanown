# Nanown

A tool for identifying, evaluating, and exploiting timing
vulnerabilities remotely.  This is part of the output from a research
effort [discussed at BlackHat 2015](https://www.blackhat.com/us-15/briefings.html#web-timing-attacks-made-practical).
This project is still highly experimental and not particularly easy to
use at this point.

# Installation

Linux and Python 3.4+ are required.  Yes, really, your Python needs to
be that new.  You will also need to install the following libraries and modules:

```bash
sudo apt-get install python3 python3-pip libfreetype6-dev libpcap-dev gcc python3-dev
sudo apt-get install build-essential gfortran libatlas-base-dev

git clone https://github.com/ecbftw/nanown.git
cd nanown

pip3 install -r requirements.txt
```

Then build the `nanown-listen` tool with:
```bash
cd src 
./compile.sh
```

That will create the `nanown-listen` binary in `nanown`'s root directory.

To run any of the other scripts, change to the `nanown` root directory
and run them directly from there.  E.g.:
```
./train ...args...
./graph ...args...
```


# Usage

Our goal for a usage workflow is this:

1. Based on example HTTP requests, and test cases supplied by the user,
   a script generator creates a new script.  This new script serves
   as the sample collection script, customized for your web
   application.

2. After collecting samples using the script from step 1, you run a
   mostly automated script to train and test various classifiers on your
   samples.  This will then tell you how many samples you need to
   reliably detect the timing difference.

3. Given the output from step 2 and inputs to step 1, a second script
   generator creates an attack script for you as a starting point.  You
   customize this and run your attacks.

Sounds great, yeah?  Well steps 1 and 3 aren't quite implemented yet. =\

If you are really dying to use this code right now, just make a copy of
the `sampler` script and hack on it until it sends HTTP requests
that your targeted web application expects.  Be sure to define the test
cases appropriately. An example sampler script can be found at
`examples/blackhat/jregistrate-sampler`. 

Run the sampler to collect at least 50,000 samples for each the train, test and
train_null data sets (150,000 samples total).  NOTE: Your sampler script must be
run as `root` so it can tweak local networking settings and sniff packets.

Next you can move on to step 2, where you simply run the train script
against the database created by your sampler script:
```
./train mysamples.db
```
This will run for a while.  If you cancel out and re-run it, it will
pick up where it left off.  Pay special attention to the final results
it prints out.  This will tell you how many samples are needed to
distinguish between the test cases.  Do a little math on your own to
decide how feasible your overall attack will be.

Finally, we come to step 3.  If you choose to carry out an attack, you
will need to implement your own attack script that collects batches of
samples, distinguishes between them using the best classifier available
(from step 2) and then repeats as needed.  Consider starting with the
sample script at `examples/blackhat/jregistrate-attack`.

Any questions?  See the source, watch our BlackHat presentation, read
our research paper, or [post an issue](https://github.com/ecbftw/nanown/issues) on GitHub.


# License

Unless otherwise indicated in the source code, this software is licensed
under the GNU GPL version 3.  See the LICENSE file for details.


# Contributing

We certainly welcome and encourage code contributions, no matter how
small. Currently, this GitHub repository is a mirror of an SVN
repository. Please don't submit pull requests.  Instead, just contact us
through the issue tracker and send us a patch if needed.  We may switch
to git later.
