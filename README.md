# nsxvansible



### nsxraml


### nsxansible & nsxvansible


git clone https://github.com/vmware/nsxansible.git
cd nsxansible
rm .git -Rf
cd ..
git clone --no-checkout https://github.com/germanium-git/nsxvansible.git nsxansible/nsxansible.tmp
mv nsxansible/nsxansible.tmp/.git/ nsxansible/
rmdir nsxansible/nsxansible.tmp
cd nsxansible
git reset --hard HEAD
git fetch


### Setting the environment

Update the path to nsxraml file in answerfile.yml
