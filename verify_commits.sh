set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# check for uncomitted changes
git update-index --refresh || (echo -e "${RED}You have uncomitted changes. Stash or commit before verification.${NC}" && exit 1)

# create ephemeral gnupg folder
TLDIR=$(git rev-parse --show-toplevel)
GH=$TLDIR/.gpg
mkdir $GH && echo "INFO: Temporary gnupg home '.gpg' created." || (echo -e "${RED}ERROR: Folder '.gpg' already exists. Please remove before verification.${NC}" && exit 1)

# get git infos
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
COMMITS=( $(git log --pretty=format:'%H') )
NO_COMMITS=${#COMMITS[@]}
NO_UNTRUSTED_COMMITS=0
UNTRUSTED_COMMITS=()
echo Current Branch: $CURRENT_BRANCH
echo Number of commits to verify: $NO_COMMITS
echo Commits: ${COMMITS[*]}
printf "\n"

for NUM in "${!COMMITS[@]}";
do
    IDX=$(($NO_COMMITS-$NUM-1))
    if [ $IDX -eq 0 ];
    then
        # cleanup
        rm -r $GH
        git checkout $CURRENT_BRANCH

        # return results
        printf "\n${YELLOW}### RESULTS ###${NC}\n"
        if [ $NO_UNTRUSTED_COMMITS -ge 1 ];
        then
            echo -e "${RED}ERROR: ${NO_UNTRUSTED_COMMITS} untrusted commits.${NC}"
            printf '%s\n' "${UNTRUSTED_COMMITS[@]}" && exit 1
        else
            echo -e "${GREEN}Trust all the commits!?${NC}"
        fi
    else
        printf "${YELLOW}${NUM}. STATUS: - Trust base commit ${COMMITS[$IDX]}: '$(git log --format=%B -n 1 ${COMMITS[$IDX]}).'\n           - Verifying commit ${COMMITS[$(($IDX-1))]}: '$(git log --format=%B -n 1 ${COMMITS[$(($IDX-1))]}).${NC}'\n"
        # slow down
        sleep 0.001

        # checkout the commit for verification
        git checkout ${COMMITS[$IDX]} --quiet && echo -e "INFO: git - HEAD is now at ${COMMITS[$IDX]}." || (echo -e "${RED}ERROR: Checking out commit ${COMMITS[$IDX]} failed.${NC}" && exit 1)

        # create commit gnupg home folder
        GHC=$GH/$IDX
        mkdir $GHC && echo "INFO: Temporary gnupg home '$GHC' created." || (echo -e "${RED}ERROR: Folder '$GHC' already exists. Suspicious! Please check.${NC}" && exit 1)

        # import current public keys to gpg
        GNUPGHOME=$GHC gpg --import .pubkeys/* || (echo -e "${RED}ERROR: Import of public keys failed. ${NC}" && exit 1)

        # verify next commit
        EXIT_CODE=1
        GNUPGHOME=$GHC git verify-commit ${COMMITS[$(($IDX-1))]} && EXIT_CODE=0 || EXIT_CODE=1
        if  [ ${EXIT_CODE} -eq 0 ];
        then
            echo -e "${GREEN}${NUM}. STATUS: SUCCESSFUL VAlIDATION of ${COMMITS[$(($IDX-1))]}.${NC}"
        else
            NO_UNTRUSTED_COMMITS=$((${NO_UNTRUSTED_COMMITS}+1))
            UNTRUSTED_COMMITS+=( "${COMMITS[$(($IDX-1))]}: '$(git log --format=%B -n 1 ${COMMITS[$(($IDX-1))]})" )
            echo -e "${RED}${NUM}. ERROR: VALIDATION FAILED for ${COMMITS[$(($IDX-1))]}.${NC}"
        fi

        printf "\n"
    fi
done

